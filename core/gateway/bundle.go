// Package gateway builds a private Docker Compose deployment for a LAN gateway.
package gateway

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"net/url"
	"strings"
	"unicode"
)

//go:embed deployment/* ethernet
var deployment embed.FS

type Request struct {
	LANAddress, Subscription, UserAgent, HWID string
	Port                                      int
}

type settings struct {
	LANAddress string            `json:"lan"`
	Port       int               `json:"port"`
	Password   string            `json:"password"`
	URL        string            `json:"url,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
}

func parseSubscription(input string) (string, []byte, error) {
	const max = 2 << 20
	if len(input) > max {
		return "", nil, errors.New("Подписка превышает 2 МиБ.")
	}
	s := strings.TrimSpace(input)
	for _, prefix := range []string{"happ://add/", "incy://import/", "blacktemple://import/", "happ://https://", "happ://http://"} {
		if !strings.HasPrefix(strings.ToLower(s), prefix) {
			continue
		}
		if strings.HasPrefix(prefix, "happ://http") {
			s = s[len("happ://"):]
		} else {
			s = s[len(prefix):]
		}
		if !strings.HasPrefix(strings.ToLower(s), "http://") && !strings.HasPrefix(strings.ToLower(s), "https://") {
			decoded, err := url.PathUnescape(s)
			if err != nil {
				return "", nil, errors.New("Повреждена ссылка импорта подписки.")
			}
			s = decoded
		}
		break
	}
	if strings.HasPrefix(strings.ToLower(s), "happ://crypt") {
		return "", nil, errors.New("Для внешнего шлюза запросите у провайдера обычную ссылку подписки или список серверов. Защищённая ссылка Happ Crypt требует ключа провайдера.")
	}
	if strings.HasPrefix(strings.ToLower(s), "http://") || strings.HasPrefix(strings.ToLower(s), "https://") {
		u, err := url.Parse(s)
		if err != nil || u.Hostname() == "" || strings.IndexFunc(s, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
			return "", nil, errors.New("Проверьте адрес подписки HTTP(S).")
		}
		// A GitHub blob page serves HTML. Use the raw file in public repositories.
		parts := strings.SplitN(strings.TrimPrefix(u.EscapedPath(), "/"), "/", 4)
		if u.Scheme == "https" && u.Host == "github.com" && len(parts) == 4 && parts[2] == "blob" {
			return "https://raw.githubusercontent.com/" + parts[0] + "/" + parts[1] + "/" + parts[3], nil, nil
		}
		return s, nil, nil
	}
	if !strings.Contains(s, "://") {
		flat := strings.Join(strings.Fields(s), "")
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			decoded, err := enc.DecodeString(flat)
			if err == nil && bytes.Contains(decoded, []byte("://")) {
				s = string(decoded)
				break
			}
		}
	}
	seen := map[string]bool{}
	var links []string
	s = strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\r", "\n")
	for i, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		scheme, rest, ok := strings.Cut(line, "://")
		switch strings.ToLower(scheme) {
		case "vless", "vmess", "ss", "ssr", "trojan", "hysteria", "hysteria2", "hy2", "tuic", "anytls", "mierus":
		default:
			ok = false
		}
		if !ok || rest == "" || strings.HasPrefix(rest, "#") || strings.IndexFunc(line, unicode.IsControl) >= 0 {
			return "", nil, fmt.Errorf("Строка %d не содержит поддерживаемой ссылки VPN-сервера.", i+1)
		}
		identity, _, _ := strings.Cut(line, "#")
		if !seen[identity] {
			seen[identity] = true
			links = append(links, line)
		}
	}
	if len(links) < 2 {
		return "", nil, errors.New("Для автоматического переключения нужны как минимум две разные ссылки VPN-серверов.")
	}
	return "", []byte(strings.Join(links, "\n") + "\n"), nil
}

func randomSecret() (string, error) {
	var b [24]byte
	_, err := rand.Read(b[:])
	return hex.EncodeToString(b[:]), err
}

// Bundle handles secrets in memory. Only the owner should receive the archive.
func Bundle(r Request) ([]byte, error) {
	ip, err := netip.ParseAddr(strings.TrimSpace(r.LANAddress))
	if err != nil || !ip.Is4() || !ip.IsPrivate() {
		return nil, errors.New("Укажите частный IPv4-адрес постоянно включённого компьютера или NAS в домашней сети.")
	}
	if r.Port == 0 {
		r.Port = 1080
	}
	if r.Port < 1 || r.Port > 65535 {
		return nil, errors.New("Порт SOCKS5 должен быть от 1 до 65535.")
	}
	source, feed, err := parseSubscription(r.Subscription)
	if err != nil {
		return nil, err
	}
	cfg := settings{LANAddress: ip.String(), Port: r.Port, URL: source, Headers: map[string]string{}}
	for k, v := range map[string]string{"User-Agent": r.UserAgent, "X-HWID": r.HWID} {
		if v == "" {
			continue
		}
		if len(v) > 512 || strings.IndexFunc(v, func(r rune) bool { return r < 32 || r > 126 }) >= 0 || source == "" {
			return nil, errors.New("Параметры провайдера применяются к URL и должны состоять из печатных символов ASCII.")
		}
		cfg.Headers[k] = v
	}
	cfg.Password, err = randomSecret()
	if err != nil {
		return nil, err
	}
	token, err := randomSecret()
	if err != nil {
		return nil, err
	}
	encoded, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)
	add := func(name string, data []byte) error {
		head := &zip.FileHeader{Name: name, Method: zip.Deflate}
		head.SetMode(0600)
		w, err := writer.CreateHeader(head)
		if err == nil {
			_, err = w.Write(data)
		}
		return err
	}
	vars := strings.NewReplacer("@LAN@", ip.String(), "@PORT@", fmt.Sprint(r.Port), "@PASSWORD@", cfg.Password, "@TOKEN@", token)
	for _, file := range []struct{ source, target string }{
		{"compose.yaml", "compose.yaml"}, {"Dockerfile", "service/Dockerfile"}, {"gateway.py", "service/gateway.py"},
		{"config.json", "config/config.yaml"}, {"readme.md", "README.md"},
	} {
		data, err := deployment.ReadFile("deployment/" + file.source)
		if err != nil {
			return nil, err
		}
		if err = add(file.target, []byte(vars.Replace(string(data)))); err != nil {
			return nil, err
		}
	}
	err = fs.WalkDir(deployment, "ethernet", func(name string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		data, err := deployment.ReadFile(name)
		if err != nil {
			return err
		}
		return add(name, []byte(vars.Replace(string(data))))
	})
	if err != nil {
		return nil, err
	}
	if err = add("config/source.json", encoded); err != nil {
		return nil, err
	}
	if feed != nil {
		if err = add("config/servers.txt", feed); err != nil {
			return nil, err
		}
	}
	if err = writer.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
