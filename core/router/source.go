package router

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"unicode"
)

type source struct {
	url, inline string
	count       int
	encrypted   bool
}

func parseSource(input string) (source, error) {
	s := strings.TrimSpace(input)
	if s == "" || len(s) > 2<<20 {
		return source{}, errors.New("Нужна ссылка на подписку или список серверов размером до 2 МБ.")
	}
	l := strings.ToLower(s)
	for _, prefix := range []string{"happ://add/", "incy://import/", "blacktemple://import/", "happ://https://", "happ://http://"} {
		if !strings.HasPrefix(l, prefix) {
			continue
		}
		if strings.HasPrefix(prefix, "happ://http") {
			s = s[len("happ://"):]
		} else {
			s = s[len(prefix):]
		}
		if !(strings.HasPrefix(strings.ToLower(s), "https://") || strings.HasPrefix(strings.ToLower(s), "http://")) {
			u, err := url.PathUnescape(s)
			if err != nil {
				return source{}, errors.New("Повреждена ссылка импорта приложения.")
			}
			s = u
		}
		l = strings.ToLower(s)
		break
	}
	if strings.HasPrefix(l, "happ://crypt") {
		u, e := url.Parse(s)
		if e != nil || len(u.Path) < 2 || !(u.Host == "crypt" || u.Host == "crypt2" || u.Host == "crypt3" || u.Host == "crypt4") {
			return source{}, errors.New("Неизвестный формат зашифрованной ссылки Happ.")
		}
		return source{url: s, encrypted: true}, nil
	}
	if strings.HasPrefix(l, "https://") || strings.HasPrefix(l, "http://") {
		u, err := url.Parse(s)
		if err != nil || u.Hostname() == "" || u.Opaque != "" || strings.IndexFunc(s, unicode.IsSpace) >= 0 {
			return source{}, errors.New("Проверьте адрес подписки HTTP(S).")
		}
		return source{url: s}, nil
	}
	if !strings.Contains(s, "://") {
		clean := strings.Join(strings.Fields(s), "")
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			b, err := enc.DecodeString(clean)
			if err == nil && strings.Contains(string(b), "://") {
				s = string(b)
				break
			}
		}
	}
	var lines []string
	seen := map[string]bool{}
	multiEndpoint := false
	s = strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\r", "\n")
	for index, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		scheme, payload, ok := strings.Cut(line, "://")
		if !ok || payload == "" || strings.HasPrefix(payload, "#") || strings.IndexFunc(line, unicode.IsControl) >= 0 {
			return source{}, fmt.Errorf("Строка %d не содержит корректной ссылки сервера. Вставьте ссылку подписки или по одной ссылке сервера на строку.", index+1)
		}
		// Match the share-link normalizer in AWG Manager v2.19.25. The
		// panel validates credentials and transports using its native parser.
		switch strings.ToLower(scheme) {
		case "vless", "trojan", "ss", "hysteria2", "hy2", "naive+http", "naive+https", "vpn":
		case "mieru", "mierus", "tt":
			multiEndpoint = true
		default:
			return source{}, fmt.Errorf("Формат ссылки в строке %d не поддерживается импортом подписок AWG Manager. Вставьте совместимую ссылку провайдера.", index+1)
		}
		if !seen[line] {
			seen[line] = true
			lines = append(lines, line)
		}
	}
	if len(lines) < 2 && !multiEndpoint {
		return source{}, errors.New("Для автоматического выбора нужны хотя бы два разных сервера.")
	}
	return source{inline: strings.Join(lines, "\n"), count: len(lines)}, nil
}
