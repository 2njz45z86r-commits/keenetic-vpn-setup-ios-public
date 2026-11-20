package router

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
)

var buildArch = map[string]string{
	"aarch64-3.10": "f66e207b18279705f973b2287ad6734749eda31dd904957d36b0e043a5c61554",
	"mipsel-3.4":   "96d726148c6272148bb5101e3a8d93a27f02b96458b3f6391494a5478d82f454",
	"mips-3.4":     "89565c78e0211354031b43f2eb14a9453da3eb748874b57c47baf695e21c17af",
}

var keeneticArchSuffix = regexp.MustCompile(`(?:_kn(?:[._-]?[0-9]+)*|-kn)$`)

var errEntwareShell = errors.New("Проверьте порт оболочки Entware в журнале запуска OPKG. Штатная командная строка KeeneticOS использует другой режим. Для установок Entware подходят поддерживаемый USB-накопитель, M.2 или внутреннее хранилище конкретной модели.")

func packageArchitecture(output string) (string, error) {
	var chosen string
	var sawArchitecture bool
	for _, line := range strings.Split(output, "\n") {
		f := strings.Fields(line)
		if len(f) != 3 || f[0] != "arch" {
			continue
		}
		if _, err := strconv.ParseUint(f[2], 10, 32); err != nil {
			continue
		}
		sawArchitecture = true
		switch f[1] {
		case "all", "any", "noarch":
			continue
		}
		arch := keeneticArchSuffix.ReplaceAllString(f[1], "")
		if buildArch[arch] == "" {
			return "", errors.New("В списке архитектур Entware есть платформа, для которой у мастера нет проверенного пакета AWG Manager.")
		}
		if chosen != "" && chosen != arch {
			return "", errors.New("OPKG указал несколько разных архитектур процессора. Проверьте источники пакетов Entware для своей модели.")
		}
		chosen = arch
	}
	if !sawArchitecture {
		return "", errEntwareShell
	}
	if chosen == "" {
		return "", errors.New("OPKG не указал архитектуру процессора. Проверьте установку Entware для своей модели.")
	}
	return chosen, nil
}

func inventory(ctx context.Context, c remote, r *Result) error {
	data, err := c.Run(ctx, "test -x /bin/ndmc && /opt/bin/opkg print-architecture", nil, 16384)
	if err != nil {
		return errEntwareShell
	}
	r.Architecture, err = packageArchitecture(string(data))
	if err != nil {
		return err
	}
	data, err = c.Run(ctx, "/opt/bin/opkg list-installed awg-manager", nil, 65536)
	if err != nil {
		return errors.New("Не удалось прочитать список пакетов Entware.")
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) >= 3 && f[0] == "awg-manager" {
			r.PanelVersion = f[2]
		}
	}
	return nil
}

func managementOn(ctx context.Context, c *sshRouter) (*management, error) {
	port := 2222
	// Read the configured port without sending the settings file to the UI.
	data, err := c.Run(ctx, "cat /opt/etc/awg-manager/settings.json", nil, 4<<20)
	if err == nil {
		var settings struct{ Server struct{ Port int } }
		if json.Unmarshal(data, &settings) == nil && settings.Server.Port > 0 && settings.Server.Port <= 65535 {
			port = settings.Server.Port
		}
	}
	for _, host := range []string{"127.0.0.1", c.ip} {
		m := newManagement(c, host, port)
		probe, cancel := context.WithTimeout(ctx, 3*time.Second)
		var h struct{ Version string }
		err = m.call(probe, "GET", "/api/health", nil, &h, true)
		cancel()
		if err == nil && h.Version != "" {
			return m, nil
		}
	}
	return nil, errors.New("Пакет AWG Manager установлен, но его служба не отвечает. Проверьте S99awg-manager и привязку в настройках панели.")
}

func Inspect(ctx context.Context, c Credentials) (Result, error) {
	var r Result
	router, fingerprint, err := connect(ctx, c)
	r.Fingerprint = fingerprint
	if err != nil {
		return r, err
	}
	defer router.client.Close()
	stop := context.AfterFunc(ctx, func() { router.client.Close() })
	defer stop()
	if err = inventory(ctx, router, &r); err != nil {
		return r, err
	}
	if r.PanelVersion == "" {
		if err = checkPanelReady(ctx, router, &r); err != nil {
			return r, err
		}
		r.Message = "Роутер готов к установке AWG Manager и движка."
		return r, nil
	}
	m, err := managementOn(ctx, router)
	if err != nil {
		return r, err
	}
	if err = m.open(ctx, c); err != nil {
		return r, err
	}
	defer closePanel(m)
	st, err := getStatus(ctx, m)
	if err != nil {
		return r, err
	}
	r.EngineVersion = st.CurrentVersion
	if r.EngineVersion == "" {
		r.EngineVersion = st.Version
	}
	r.Message = "Панель доступна."
	if !st.ProxyComponent {
		return r, panelFailure("proxy")
	}
	if !*st.NDMSProxyEnabled {
		return r, errors.New("В AWG Manager отключено создание штатного Proxy. Проверьте действующие туннели и включите опцию в настройках Sing-box.")
	}
	return r, nil
}

func closePanel(m *management) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = m.call(ctx, "POST", "/api/auth/logout", nil, nil, false)
}

func lockApply(ctx context.Context, c *sshRouter) (func(), error) {
	s, err := c.client.NewSession()
	if err != nil {
		return nil, errors.New("Не удалось начать сеанс настройки.")
	}
	in, _ := s.StdinPipe()
	out, err := s.StdoutPipe()
	if err != nil {
		s.Close()
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { s.Close() })
	unlock := func() { in.Close(); s.Close(); stop() }
	err = s.Start("umask 077; d=/tmp/keenetic-vpn-setup.lock; mkdir \"$d\" || exit 1; trap 'rmdir \"$d\"' EXIT; trap 'exit 1' HUP INT TERM; echo locked; cat >/dev/null")
	if err == nil {
		line, _ := bufio.NewReader(out).ReadString('\n')
		if strings.TrimSpace(line) == "locked" {
			return func() { in.Close(); s.Wait(); s.Close(); stop() }, nil
		}
	}
	unlock()
	return nil, errors.New("На роутере уже выполняется настройка или недоступен /tmp. Повторите после завершения.")
}

func Apply(ctx context.Context, c Credentials, o Options) (Result, error) {
	var r Result
	src, err := parseSource(o.SubscriptionURL)
	if err != nil {
		return r, err
	}
	headers, err := validateHeaders(o.Headers)
	if err != nil {
		return r, err
	}
	if src.inline != "" && len(headers) > 0 {
		return r, errors.New("Для вставленного списка ссылки не требуют заголовков HTTP.")
	}
	label := strings.TrimSpace(o.Label)
	if label == "" {
		label = "VPN"
	}
	if len([]rune(label)) > 80 || strings.IndexFunc(label, unicode.IsControl) >= 0 {
		return r, errors.New("Название должно содержать от 1 до 80 печатных символов.")
	}
	if src.inline != "" {
		digest := sha256.Sum256([]byte(src.inline))
		label += fmt.Sprintf(" [%x]", digest[:6])
	}
	router, key, err := connect(ctx, c)
	r.Fingerprint = key
	if err != nil {
		return r, err
	}
	defer router.client.Close()
	stop := context.AfterFunc(ctx, func() { router.client.Close() })
	defer stop()
	release, err := lockApply(ctx, router)
	if err != nil {
		return r, err
	}
	defer release()
	if err = inventory(ctx, router, &r); err != nil {
		return r, err
	}
	if r.PanelVersion == "" {
		if !o.InstallMissing {
			return r, errors.New("AWG Manager отсутствует. Разрешите установку в мастере.")
		}
		if err = installPanel(ctx, router, r.Architecture); err != nil {
			return r, err
		}
		r.InstalledPanel = true
		if err = inventory(ctx, router, &r); err != nil {
			return r, err
		}
		if r.PanelVersion == "" {
			return r, errors.New("После установки пакет AWG Manager не зарегистрирован в Entware.")
		}
	}
	m, err := managementOn(ctx, router)
	for attempts := 0; err != nil && r.InstalledPanel && attempts < 8; attempts++ {
		select {
		case <-ctx.Done():
			return r, ctx.Err()
		case <-time.After(time.Second):
		}
		m, err = managementOn(ctx, router)
	}
	if err != nil {
		return r, err
	}
	if err = m.open(ctx, c); err != nil {
		return r, err
	}
	defer closePanel(m)
	return workflow(ctx, m, &r, o, src, label, headers, func(ctx context.Context, p int, port int) error {
		return verifyPath(ctx, router, p, port)
	}, func(ctx context.Context, id, expected string) bool {
		raw, err := router.Run(ctx, "cat /opt/etc/awg-manager/subscriptions.json", nil, 12<<20)
		if err != nil {
			return false
		}
		var list []struct{ ID, Inline string }
		if json.Unmarshal(raw, &list) != nil {
			return false
		}
		for _, item := range list {
			if item.ID == id {
				return strings.TrimSpace(item.Inline) == expected
			}
		}
		return false
	})
}

func verifyPath(ctx context.Context, r *sshRouter, index, port int) error {
	if index < 0 || index > 255 || port < 1 || port > 65535 {
		return errors.New("Панель вернула ошибочные параметры Proxy.")
	}
	name := "Proxy" + strconv.Itoa(index)
	cmd := fmt.Sprintf("/bin/ndmc -c 'show running-config' | /opt/bin/busybox awk '$1==\"interface\" {active=($2==\"%s\")} /^!/ {active=0} active && $1==\"proxy\" && ($2==\"protocol\" || $2==\"upstream\") {print $2,$3,$4}'", name)
	b, err := r.Run(ctx, cmd, nil, 4096)
	if err != nil || !strings.Contains(string(b), "protocol socks5") || !regexp.MustCompile("(?m)^upstream 127\\.0\\.0\\.1 "+strconv.Itoa(port)+"\\s*$").Match(b) {
		return errors.New("Привязка созданного Proxy к локальному порту подписки пока не подтверждена. Повторите проверку.")
	}
	connected := false
	for tries := 0; tries < 10; tries++ {
		up, e := r.Run(ctx, "/bin/ndmc -c 'show interface "+name+"' | /opt/bin/busybox awk '$1==\"connected:\" {print $2;exit}'", nil, 128)
		if e == nil && strings.TrimSpace(string(up)) == "yes" {
			connected = true
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
	if !connected {
		return errors.New("Нативный интерфейс Proxy пока не подключён. Проверьте «Клиент прокси» и повторите.")
	}
	proxy, _ := url.Parse("http://127.0.0.1:" + strconv.Itoa(port))
	t := &http.Transport{Proxy: http.ProxyURL(proxy), DisableKeepAlives: true, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return r.dialAPI(ctx, "127.0.0.1", port) }}
	defer t.CloseIdleConnections()
	client := &http.Client{Transport: t, Timeout: 14 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	for _, target := range []string{"https://cp.cloudflare.com/generate_204", "https://www.cloudflare.com/cdn-cgi/trace", "https://www.gstatic.com/generate_204"} {
		req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err == nil {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 8193))
			resp.Body.Close()
			if strings.HasSuffix(target, "generate_204") && resp.StatusCode == 204 {
				return nil
			}
			if strings.HasSuffix(target, "cdn-cgi/trace") && resp.StatusCode == 200 && len(b) <= 8192 && validTrace(string(b)) {
				return nil
			}
		}
	}
	return errors.New("Группа и нативный Proxy созданы. HTTPS через группу не подтверждён. Проверьте доступность серверов и повторите с тем же ключом.")
}

func validTrace(body string) bool {
	fields := map[string]string{}
	for _, line := range strings.Split(body, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok {
			fields[k] = v
		}
	}
	ip := net.ParseIP(fields["ip"])
	return fields["h"] == "www.cloudflare.com" && fields["visit_scheme"] == "https" && ip != nil && ip.IsGlobalUnicast() && !ip.IsPrivate()
}
