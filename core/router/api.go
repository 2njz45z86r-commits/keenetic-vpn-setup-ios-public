package router

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"time"
)

type management struct {
	client *http.Client
	base   string
}

func newManagement(r *sshRouter, host string, port int) *management {
	t := &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return r.dialAPI(ctx, host, port) }}
	j, _ := cookiejar.New(nil)
	return &management{&http.Client{Transport: t, Jar: j, Timeout: 100 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}, "http://127.0.0.1"}
}

func (m *management) call(ctx context.Context, method, path string, payload, out any, wrapped bool) error {
	var body []byte
	var err error
	if payload != nil {
		body, err = json.Marshal(payload)
		if err != nil {
			return errors.New("Ошибка подготовки запроса к панели.")
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, m.base+path, bytes.NewReader(body))
	if err != nil {
		return errors.New("Недопустимый запрос к панели.")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := m.client.Do(req)
	if err != nil {
		return errors.New("Панель AWG Manager не ответила через SSH. Проверьте службу и порт.")
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, (12<<20)+1))
	if err != nil || len(b) > 12<<20 {
		return errors.New("Ответ панели неполный или слишком большой.")
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		switch resp.StatusCode {
		case 401, 403:
			return errors.New("Панель отклонила доступ. Проверьте учётную запись Entware и разрешение входа в AWG Manager.")
		case 429:
			return errors.New("Панель временно ограничила вход. Дождитесь окончания ограничения.")
		}
		return fmt.Errorf("Панель вернула HTTP %d. Проверьте журнал операции в AWG Manager.", resp.StatusCode)
	}
	if wrapped {
		var envelope struct {
			Success bool
			Data    json.RawMessage
		}
		if json.Unmarshal(b, &envelope) != nil || !envelope.Success {
			return errors.New("Панель не подтвердила операцию.")
		}
		b = envelope.Data
	}
	if out != nil && json.Unmarshal(b, out) != nil {
		return errors.New("Неподдерживаемый формат ответа AWG Manager.")
	}
	return nil
}

func (m *management) open(ctx context.Context, c Credentials) error {
	var state struct {
		AuthDisabled  bool
		Authenticated bool
	}
	if err := m.call(ctx, "GET", "/api/auth/status", nil, &state, false); err != nil {
		return err
	}
	if state.AuthDisabled || state.Authenticated {
		return nil
	}
	var result struct{ Success bool }
	err := m.call(ctx, "POST", "/api/auth/login", map[string]string{"login": c.Username, "password": c.Password, "method": "entware"}, &result, false)
	if err != nil {
		return err
	}
	if !result.Success {
		return errors.New("AWG Manager не подтвердил вход через Entware.")
	}
	return nil
}

type status struct {
	Installed, Running, ProxyComponent                                      bool
	NDMSProxyEnabled                                                        *bool
	TunnelCount                                                             int
	Version, CurrentVersion, RequiredVersion, RequiredSHA256, CurrentSHA256 string
}
type header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
type member struct{ Key, Protocol, Tag string }
type subscription struct {
	ID, Label, URL, Mode, SelectorTag string
	FilterInclude, FilterExclude      string
	Enabled, IsInline                 bool
	ProxyIndex                        *int
	ListenPort                        int
	MemberTags                        []string
	ExcludedTags                      []string
	Members                           []member
	RejectedMembers                   []struct{}
	Headers                           []header
}

const subscriptions = "/api/singbox/subscriptions"

func getStatus(ctx context.Context, m *management) (status, error) {
	var st status
	err := m.call(ctx, "GET", "/api/singbox/status", nil, &st, true)
	if err == nil && st.NDMSProxyEnabled == nil {
		err = errors.New("Установленная панель не сообщает режим нативного прокси. Обновите её до совместимого выпуска.")
	}
	return st, err
}

func validateHeaders(values map[string]string) ([]header, error) {
	var out []header
	for k, v := range values {
		if len(k) > 80 || len(v) > 4096 || k == "" || strings.ContainsAny(k, "()<>@,;:\\\"/[]?={} \t\r\n") || strings.ContainsAny(v, "\r\n") {
			return nil, errors.New("Недопустимый заголовок подписки.")
		}
		for _, r := range k {
			if r < 33 || r > 126 {
				return nil, errors.New("Недопустимое имя заголовка.")
			}
		}
		switch strings.ToLower(k) {
		case "host", "connection", "content-length", "transfer-encoding", "proxy-authorization", "cookie":
			return nil, errors.New("Этот служебный заголовок запрещён.")
		}
		out = append(out, header{k, v})
	}
	return out, nil
}
