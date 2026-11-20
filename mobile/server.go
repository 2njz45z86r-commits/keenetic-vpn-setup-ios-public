// Package mobile runs the same local setup wizard on desktop and mobile.
package mobile

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"time"

	"keeneticsetup/core/gateway"
	"keeneticsetup/core/router"
)

//go:embed ui/*
var assets embed.FS

type service struct {
	server              *http.Server
	token, origin, addr string
	done                chan struct{}
	cancel              context.CancelFunc
	operation           sync.Mutex
	// Candidate and trusted identities are scoped to this single local application session.
	host               string
	port               int
	candidate, trusted string
	lastProxy          string
}

var instance struct {
	sync.Mutex
	current *service
}

// Start opens a fresh, authenticated loopback session. The URL must not be logged.
func Start() (string, error) {
	instance.Lock()
	defer instance.Unlock()
	if s := instance.current; s != nil {
		return s.origin + "/#" + s.token, nil
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	var key [32]byte
	if _, err = rand.Read(key[:]); err != nil {
		listener.Close()
		return "", err
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &service{token: base64.RawURLEncoding.EncodeToString(key[:]), addr: listener.Addr().String(), done: make(chan struct{}), cancel: cancel}
	s.origin = "http://" + s.addr
	s.server = &http.Server{Handler: s, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, IdleTimeout: 45 * time.Second,
		MaxHeaderBytes: 16 << 10, BaseContext: func(net.Listener) context.Context { return ctx }}
	instance.current = s
	go func() { _ = s.server.Serve(listener); cancel(); close(s.done) }()
	return s.origin + "/#" + s.token, nil
}

func Stop() {
	instance.Lock()
	defer instance.Unlock()
	if s := instance.current; s != nil {
		s.cancel()
		_ = s.server.Close()
		instance.current = nil
	}
}

// Wait blocks until the application is closed by its owner.
func Wait() {
	instance.Lock()
	s := instance.current
	instance.Unlock()
	if s != nil {
		<-s.done
	}
}

func respond(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

type request struct {
	Headers                                                    map[string]string
	Host, Username, Password, Fingerprint, Label, Subscription string
	Port                                                       int
	Install                                                    bool
}

func (s *service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
	if r.Host != s.addr {
		http.Error(w, "Локальный сеанс недоступен", http.StatusForbidden)
		return
	}
	switch r.URL.Path {
	case "/", "/app.css", "/app.js", "/gateway.js":
		if r.Method != "GET" {
			w.WriteHeader(405)
			return
		}
		file, mime := "index.html", "text/html; charset=utf-8"
		if r.URL.Path == "/app.css" {
			file, mime = "app.css", "text/css; charset=utf-8"
		}
		if r.URL.Path == "/app.js" {
			file, mime = "app.js", "text/javascript; charset=utf-8"
		}
		if r.URL.Path == "/gateway.js" {
			file, mime = "gateway.js", "text/javascript; charset=utf-8"
		}
		b, err := assets.ReadFile("ui/" + file)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", mime)
		_, _ = w.Write(b)
		return
	case "/api/inspect", "/api/trust", "/api/apply", "/api/attach", "/api/close", "/api/gateway":
	default:
		http.NotFound(w, r)
		return
	}
	if r.Method != "POST" {
		w.WriteHeader(405)
		return
	}
	if r.Header.Get("Origin") != s.origin || subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+s.token)) != 1 {
		respond(w, 403, map[string]string{"error": "Сеанс закрыт. Откройте приложение заново."})
		return
	}
	if r.URL.Path == "/api/close" {
		if runtime.GOOS == "windows" {
			respond(w, 200, map[string]bool{"closed": true})
			go func() { time.Sleep(200 * time.Millisecond); Stop() }()
		} else {
			respond(w, 200, map[string]bool{"closed": false})
		}
		return
	}
	if !s.operation.TryLock() {
		respond(w, 409, map[string]string{"error": "Предыдущая операция ещё выполняется."})
		return
	}
	defer s.operation.Unlock()
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2<<20))
	decoder.DisallowUnknownFields()
	if r.URL.Path == "/api/gateway" {
		var settings gateway.Request
		if decoder.Decode(&settings) != nil || decoder.Decode(&struct{}{}) != io.EOF {
			respond(w, 400, map[string]string{"error": "Проверьте поля формы и размер подписки."})
			return
		}
		archive, err := gateway.Bundle(settings)
		if err != nil {
			respond(w, 422, map[string]string{"error": err.Error()})
			return
		}
		respond(w, 200, map[string][]byte{"archive": archive})
		return
	}
	var q request
	if decoder.Decode(&q) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		respond(w, 400, map[string]string{"error": "Проверьте поля формы и размер подписки."})
		return
	}
	q.Host = strings.TrimSpace(q.Host)
	ip := net.ParseIP(q.Host)
	if ip == nil || ip.To4() == nil || !ip.IsPrivate() || q.Port < 1 || q.Port > 65535 {
		respond(w, 400, map[string]string{"error": "Введите локальный IPv4-адрес роутера и порт SSH Entware."})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Minute)
	defer cancel()
	c := router.Credentials{Host: q.Host, Port: q.Port, Username: q.Username}
	var result router.Result
	var err error
	switch r.URL.Path {
	case "/api/inspect":
		s.host, s.port, s.trusted, s.candidate = q.Host, q.Port, "", ""
		s.lastProxy = ""
		result, err = router.Inspect(ctx, c)
		if errors.Is(err, router.ErrTrustRequired) && result.Fingerprint != "" {
			s.candidate = result.Fingerprint
			respond(w, 200, map[string]string{"fingerprint": result.Fingerprint})
			return
		}
	case "/api/trust", "/api/apply", "/api/attach":
		if s.host != q.Host || s.port != q.Port || s.candidate == "" || q.Fingerprint != s.candidate {
			respond(w, 409, map[string]string{"error": "Снова проверьте отпечаток этого роутера."})
			return
		}
		c.Password, c.Fingerprint = q.Password, q.Fingerprint
		if r.URL.Path == "/api/trust" {
			s.trusted = ""
			result, err = router.Inspect(ctx, c)
			if err == nil {
				s.trusted = q.Fingerprint
			}
		} else {
			if s.trusted != q.Fingerprint {
				respond(w, 409, map[string]string{"error": "Сначала подтвердите доступ к роутеру."})
				return
			}
			if r.URL.Path == "/api/attach" {
				if s.lastProxy == "" {
					respond(w, 409, map[string]string{"error": "Сначала проверьте подписку в этом сеансе."})
					return
				}
				var policy string
				policy, err = router.AttachCurrent(ctx, c, s.lastProxy)
				if err == nil {
					respond(w, 200, map[string]string{"policy": policy})
					return
				}
			} else {
				s.lastProxy = ""
				result, err = router.Apply(ctx, c, router.Options{SubscriptionURL: q.Subscription, Label: q.Label, InstallMissing: q.Install, Headers: q.Headers})
				if err == nil {
					s.lastProxy = result.Proxy
				}
			}
		}
	}
	if err != nil {
		msg := err.Error()
		for _, secret := range []string{q.Password, q.Subscription} {
			if secret != "" {
				msg = strings.ReplaceAll(msg, secret, "[…]")
			}
		}
		if strings.Contains(msg, "://") || len(msg) > 700 {
			msg = "Операция не завершена. Проверьте доступ к роутеру и формат подписки."
		}
		respond(w, 422, map[string]string{"error": msg})
		return
	}
	respond(w, 200, map[string]any{"result": result})
}
