package router

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

type Credentials struct {
	Host                            string
	Port                            int
	Username, Password, Fingerprint string
}

type Options struct {
	SubscriptionURL, Label string
	InstallMissing         bool
	Headers                map[string]string
}

type Result struct {
	Fingerprint, Architecture, PanelVersion, EngineVersion, Group, Proxy, Message string
	Model, Firmware                                                               string
	Profiles                                                                      int
	InstalledPanel, InstalledEngine, Imported                                     bool
}

var ErrTrustRequired = errors.New("Сверьте отпечаток SSH-ключа роутера и подтвердите его.")

type remote interface {
	Run(context.Context, string, []byte, int) ([]byte, error)
}

type sshRouter struct {
	client *ssh.Client
	ip     string
}

func lanAddress(raw string) (string, error) {
	a, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil || !(a.IsPrivate() || a.IsLinkLocalUnicast()) || !a.Is4() {
		return "", errors.New("Укажите локальный IPv4-адрес роутера в подключённой сети.")
	}
	addrs, err := net.InterfaceAddrs()
	if err == nil {
		for _, i := range addrs {
			p, e := netip.ParsePrefix(i.String())
			if e == nil && p.Contains(a) && p.Addr() != a {
				return a.String(), nil
			}
		}
	}
	// SELinux may hide interface addresses from a normal Android app.
	// The actual SSH socket on Android enforces TTL=1 before connect.
	if runtime.GOOS == "android" {
		return a.String(), nil
	}
	return "", errors.New("Этот адрес не входит в подключённую локальную сеть. Подключитесь к Wi-Fi или LAN роутера.")
}

func connect(ctx context.Context, c Credentials) (*sshRouter, string, error) {
	ip, err := lanAddress(c.Host)
	if err != nil {
		return nil, "", err
	}
	if c.Port < 1 || c.Port > 65535 {
		return nil, "", errors.New("Недопустимый SSH-порт.")
	}
	user := strings.TrimSpace(c.Username)
	if user == "" || len(user) > 128 {
		return nil, "", errors.New("Укажите имя пользователя Entware.")
	}
	addr := net.JoinHostPort(ip, strconv.Itoa(c.Port))
	dialer := net.Dialer{Timeout: 8 * time.Second}
	configureRouterDialer(&dialer)
	raw, err := dialer.DialContext(ctx, "tcp4", addr)
	if err != nil {
		return nil, "", errors.New("Порт SSH не ответил. Сверьте LAN-адрес и порт в журнале запуска Entware. Совместимость модели пока определить не удалось.")
	}
	return handshake(ctx, raw, ip, addr, user, c)
}

func handshake(ctx context.Context, raw net.Conn, ip, addr, user string, c Credentials) (*sshRouter, string, error) {
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	defer stop()
	raw.SetDeadline(time.Now().Add(20 * time.Second))
	fingerprint := ""
	wrongKey := false
	conf := &ssh.ClientConfig{User: user, HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
		fingerprint = ssh.FingerprintSHA256(key)
		if c.Fingerprint == "" {
			return ErrTrustRequired
		}
		if subtle.ConstantTimeCompare([]byte(c.Fingerprint), []byte(fingerprint)) != 1 {
			wrongKey = true
			return errors.New("ssh key changed")
		}
		return nil
	}}
	if c.Fingerprint != "" && c.Password != "" {
		conf.Auth = []ssh.AuthMethod{ssh.Password(c.Password)}
	}
	conn, ch, req, err := ssh.NewClientConn(raw, addr, conf)
	if err != nil {
		raw.Close()
		if fingerprint != "" && c.Fingerprint == "" {
			return nil, fingerprint, ErrTrustRequired
		}
		if wrongKey {
			return nil, fingerprint, errors.New("Отпечаток SSH-ключа изменился. Проверьте устройство и подтвердите его новый ключ отдельно.")
		}
		return nil, fingerprint, errors.New("Вход по SSH не удался. Проверьте логин и пароль именно Entware, версию SSH и порт.")
	}
	raw.SetDeadline(time.Time{})
	return &sshRouter{ssh.NewClient(conn, ch, req), ip}, fingerprint, nil
}

type bounded struct {
	bytes.Buffer
	max      int
	overflow bool
}

// Override Buffer's promoted ReadFrom so io.Copy cannot bypass the cap.
func (b *bounded) ReadFrom(r io.Reader) (int64, error) { return io.Copy(struct{ io.Writer }{b}, r) }
func (b *bounded) Write(p []byte) (int, error) {
	n := len(p)
	room := b.max - b.Len()
	if n > room {
		p = p[:room]
		b.overflow = true
	}
	_, err := b.Buffer.Write(p)
	return n, err
}

func (c *sshRouter) Run(ctx context.Context, cmd string, input []byte, max int) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s, err := c.client.NewSession()
	if err != nil {
		return nil, errors.New("Не удалось открыть SSH-сеанс Entware.")
	}
	defer s.Close()
	stop := context.AfterFunc(ctx, func() { s.Close() })
	defer stop()
	b := &bounded{max: max}
	s.Stdout = b
	s.Stderr = io.Discard
	s.Stdin = bytes.NewReader(input)
	if e := s.Run(cmd); e != nil {
		return nil, errors.New("Команда Entware завершилась ошибкой.")
	}
	if b.overflow {
		return nil, errors.New("Ответ устройства превышает допустимый размер.")
	}
	return b.Bytes(), nil
}

// busybox nc keeps router loopback management available even if Dropbear's
// direct-tcpip forwarding is disabled. Never put credentials in argv.
func (c *sshRouter) dialAPI(ctx context.Context, host string, port int) (net.Conn, error) {
	if host != "127.0.0.1" && host != c.ip {
		return nil, errors.New("Недопустимый адрес панели.")
	}
	if port < 1 || port > 65535 {
		return nil, errors.New("Недопустимый порт панели.")
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	s, err := c.client.NewSession()
	if err != nil {
		return nil, err
	}
	in, err := s.StdinPipe()
	if err != nil {
		s.Close()
		return nil, err
	}
	out, err := s.StdoutPipe()
	if err != nil {
		s.Close()
		return nil, err
	}
	s.Stderr = io.Discard
	if err = s.Start(fmt.Sprintf("/opt/bin/busybox nc %s %d", host, port)); err != nil {
		s.Close()
		return nil, err
	}
	a, b := net.Pipe()
	go func() { _, _ = io.Copy(in, b); in.Close() }()
	go func() { _, _ = io.Copy(b, out); b.Close(); s.Close() }()
	return a, nil
}
