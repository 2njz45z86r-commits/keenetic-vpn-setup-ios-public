package router

import (
	"context"
	"errors"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const policyAPI = "/api/access-policies"

var proxyID = regexp.MustCompile("^Proxy[0-9]{1,3}$")
var policyID = regexp.MustCompile("^Policy[0-9]{1,3}$")

type nativePolicy struct {
	Name, Description string
	Standalone        bool
	Interfaces        []struct {
		Name   string
		Denied bool
	}
}
type nativeDevice struct {
	MAC, IP, Policy string
	Active          bool
}

func singleProxy(p nativePolicy, proxy string) bool {
	n := 0
	for _, iface := range p.Interfaces {
		if iface.Denied {
			continue
		}
		if iface.Name != proxy {
			return false
		}
		n++
	}
	return n == 1 && p.Standalone
}

func localDevice(list []nativeDevice, ip string) (nativeDevice, error) {
	var found nativeDevice
	for _, d := range list {
		if !d.Active || d.IP != ip {
			continue
		}
		mac, err := net.ParseMAC(d.MAC)
		if err != nil || len(mac) != 6 || found.MAC != "" {
			return nativeDevice{}, errors.New("Роутер не смог однозначно определить это устройство.")
		}
		found = d
	}
	if found.MAC == "" {
		return found, errors.New("Роутер не видит это устройство среди активных клиентов. Подключитесь напрямую к его домашней сети.")
	}
	return found, nil
}

// AttachCurrent only moves the device observed as the SSH peer, and only after an explicit UI action.
func AttachCurrent(ctx context.Context, c Credentials, proxy string) (string, error) {
	if !proxyID.MatchString(proxy) {
		return "", errors.New("Выберите подтверждённый нативный интерфейс подписки.")
	}
	r, _, err := connect(ctx, c)
	if err != nil {
		return "", err
	}
	defer r.client.Close()
	unlock, err := lockApply(ctx, r)
	if err != nil {
		return "", err
	}
	defer unlock()
	peer, err := r.Run(ctx, "printf '%s' \"$SSH_CONNECTION\"", nil, 512)
	if err != nil {
		return "", err
	}
	fields := strings.Fields(string(peer))
	if len(fields) != 4 || net.ParseIP(fields[0]) == nil || !net.ParseIP(fields[0]).IsPrivate() {
		return "", errors.New("Не удалось определить локальный адрес устройства.")
	}
	m, err := managementOn(ctx, r)
	if err != nil {
		return "", err
	}
	if err = m.open(ctx, c); err != nil {
		return "", err
	}
	defer closePanel(m)
	return attach(ctx, m, fields[0], proxy)
}

func attach(ctx context.Context, m *management, ip, proxy string) (string, error) {
	var ds []nativeDevice
	if err := m.call(ctx, "GET", policyAPI+"/devices?refresh=true", nil, &ds, true); err != nil {
		return "", err
	}
	current, err := localDevice(ds, ip)
	if err != nil {
		return "", err
	}
	var policies []nativePolicy
	load := func() error { return m.call(ctx, "GET", policyAPI+"?refresh=true", nil, &policies, true) }
	if err = load(); err != nil {
		return "", err
	}
	label := "VPN Setup " + proxy
	var plan nativePolicy
	for _, p := range policies {
		if p.Name == current.Policy && singleProxy(p, proxy) {
			return p.Name, nil
		}
		if p.Description == label {
			if plan.Name != "" || !policyID.MatchString(p.Name) || !singleProxy(p, proxy) {
				return "", errors.New("Политика с таким именем уже существует с другими параметрами. Проверьте её в панели роутера.")
			}
			plan = p
		}
	}
	if plan.Name == "" {
		if err = m.call(ctx, "POST", policyAPI+"/create", map[string]string{"description": label}, &plan, true); err != nil {
			return "", err
		}
		if !policyID.MatchString(plan.Name) || plan.Description != label {
			return "", errors.New("Роутер не подтвердил созданную политику.")
		}
		for _, old := range policies {
			if old.Name == plan.Name {
				return "", errors.New("Список политик изменился одновременно. Повторите проверку.")
			}
		}
		// Remove only our newly created, still-unused policy if setup fails before assignment.
		cleanup := true
		defer func() {
			if !cleanup {
				return
			}
			cx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var list []nativeDevice
			var currentPolicies []nativePolicy
			if m.call(cx, "GET", policyAPI+"/devices?refresh=true", nil, &list, true) != nil {
				return
			}
			for _, d := range list {
				if d.Policy == plan.Name {
					return
				}
			}
			if m.call(cx, "GET", policyAPI+"?refresh=true", nil, &currentPolicies, true) != nil {
				return
			}
			for _, p := range currentPolicies {
				if p.Name == plan.Name && p.Description == label {
					_ = m.call(cx, "DELETE", policyAPI+"/delete?name="+plan.Name, nil, nil, true)
					return
				}
			}
		}()
		if err = m.call(ctx, "POST", policyAPI+"/permit", map[string]any{"name": plan.Name, "interface": proxy, "order": 0}, nil, true); err != nil {
			return "", err
		}
		for _, iface := range plan.Interfaces {
			if !iface.Denied && iface.Name != proxy {
				if err = m.call(ctx, "DELETE", policyAPI+"/permit?name="+plan.Name+"&interface="+url.QueryEscape(iface.Name), nil, nil, true); err != nil {
					return "", err
				}
			}
		}
		if err = m.call(ctx, "POST", policyAPI+"/standalone", map[string]any{"name": plan.Name, "enabled": true}, nil, true); err != nil {
			return "", err
		}
		if err = load(); err != nil {
			return "", err
		}
		ready := false
		for _, p := range policies {
			if p.Name == plan.Name && p.Description == label && singleProxy(p, proxy) {
				ready = true
			}
		}
		if !ready {
			return "", errors.New("Роутер не подтвердил автономную политику с единственным VPN-интерфейсом.")
		}
		cleanup = false
	}
	if err = m.call(ctx, "GET", policyAPI+"/devices?refresh=true", nil, &ds, true); err != nil {
		return "", err
	}
	still, err := localDevice(ds, ip)
	if err != nil || still.MAC != current.MAC || still.Policy != current.Policy {
		return "", errors.New("Назначение устройства изменилось. Проверьте его и повторите.")
	}
	writeErr := m.call(ctx, "POST", policyAPI+"/assign", map[string]string{"mac": current.MAC, "policy": plan.Name}, nil, true)
	if err = m.call(ctx, "GET", policyAPI+"/devices?refresh=true", nil, &ds, true); err != nil {
		return "", err
	}
	after, err := localDevice(ds, ip)
	if err == nil && after.MAC == current.MAC && after.Policy == plan.Name {
		return plan.Name, nil
	}
	if writeErr != nil {
		return "", writeErr
	}
	return "", errors.New("Назначение устройства не подтверждено. Проверьте раздел «Приоритеты подключений» на роутере.")
}
