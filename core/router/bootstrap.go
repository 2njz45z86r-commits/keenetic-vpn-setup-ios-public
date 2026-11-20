package router

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"
)

// Digests are the publisher's release digests for v2.19.25.
var panelSHA = map[string]string{
	"aarch64-3.10": "128050663fe191cb6f17dabd52aa25083f389f557357afe21b461f534cf0df3b",
	"mipsel-3.4":   "594e8482de562b80246c9acf64a9faa603a6ca48151a87b00e647b68640b4e84",
	"mips-3.4":     "82e560eafaf3b50e1bcdc87e3d68a00163b4ca9864cdfab9e0e53b3e43a55215",
}

const panelChecks = `export PATH=/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin
umask 077
msg() { echo "$1"; exit 0; }
test "$(id -u)" = 0 && test -x /bin/ndmc && test -x /opt/bin/opkg && test -x /opt/bin/busybox || msg platform
test -d /opt/etc/init.d && test -d /opt/tmp || msg entware
test -d /sys/module/wireguard || msg wireguard
for p in /opt/etc/awg-manager /opt/bin/awg-manager /var/run/awg-manager.pid /opt/etc/init.d/S99awg-manager /opt/etc/init.d/S80awg-manager /opt/lib/modules/awg_proxy /opt/share/www/awg-manager /opt/var/lock/awg-manager /opt/var/run/awg-manager /opt/etc/ndm/ifstatechanged.d/50-awg-manager.sh; do
  test ! -e "$p" && test ! -L "$p" || msg occupied
done
test -z "$(/opt/bin/busybox netstat -lnt | awk '$4 ~ /:2222$/ { print $4 }')" || msg port
/opt/bin/busybox ip -4 addr show lo | grep -q '127.0.0.1' || msg loopback
free=$(df -Pk /opt | awk 'END {print $4}')
case "$free" in ""|*[!0-9]*) msg space;; esac
test "$free" -ge 98304 || msg space
`

func panelFailure(status string) error {
	msg := map[string]string{
		"platform":       "Нужен SSH с правами root в Entware на Keenetic или Netcraze.",
		"entware":        "Подготовьте Entware на постоянном хранилище, которое поддерживает эта модель роутера.",
		"wireguard":      "Проверьте компонент WireGuard и его загрузку в настройках KeeneticOS или NetcrazeOS.",
		"proxy":          "Для установки на роутере нужен компонент «Клиент прокси». Проверьте его наличие в разделе «Обновления и компоненты» для своей модели.",
		"component-list": "Не удалось прочитать список установленных компонентов. Проверьте раздел «Обновления и компоненты» на роутере и повторите подключение.",
		"occupied":       "Найдены файлы предыдущей установки AWG Manager. Проверьте или восстановите её через обычную панель владельца.",
		"port":           "Порт панели 2222 уже занят другим процессом.",
		"loopback":       "Локальный интерфейс роутера недоступен.",
		"space":          "Для загрузки и распаковки компонентов освободите 96 МиБ на разделе Entware.",
		"lock":           "На роутере уже выполняется установка.",
		"feeds":          "Entware не смог обновить списки пакетов. Проверьте подключение и репозиторий Entware.",
		"opkg":           "Entware не завершил установку AWG Manager. Проверьте свободное место, конфликты зависимостей и журнал opkg на роутере.",
		"hash":           "Роутер не подтвердил контрольную сумму пакета.",
	}
	if m := msg[status]; m != "" {
		return errors.New(m)
	}
	return errors.New("Не удалось завершить установку панели на роутере.")
}

var terminalEscapes = regexp.MustCompile(`\x1b\[[0-?]*[ -/]*[@-~]`)

// NDMS wraps long component names across lines, even in the middle of a word.
// Read the same show version fields used by AWG Manager's ndmsinfo package.
func checkNativeComponents(version string, r *Result) error {
	var components strings.Builder
	readingComponents := false
	for _, line := range strings.Split(terminalEscapes.ReplaceAllString(version, ""), "\n") {
		line = strings.TrimSpace(line)
		key, value, field := strings.Cut(line, ":")
		if !field {
			if readingComponents {
				components.WriteString(line)
			}
			continue
		}
		value = strings.TrimSpace(value)
		readingComponents = key == "components" && components.Len() == 0
		switch {
		case readingComponents:
			components.WriteString(value)
		case key == "model" && r.Model == "":
			r.Model = value
		case key == "release" && r.Firmware == "":
			r.Firmware = value
		}
	}
	if components.Len() == 0 {
		return panelFailure("component-list")
	}
	installed := strings.FieldsFunc(components.String(), func(c rune) bool { return c == ',' || c == ' ' || c == '\t' })
	if !slices.Contains(installed, "proxy") {
		return panelFailure("proxy")
	}
	if !slices.Contains(installed, "wireguard") {
		return panelFailure("wireguard")
	}
	return nil
}

func checkPanelReady(ctx context.Context, c remote, r *Result) error {
	version, err := c.Run(ctx, "/bin/ndmc -c 'show version'", nil, 64<<10)
	if err != nil {
		return panelFailure("component-list")
	}
	if err := checkNativeComponents(string(version), r); err != nil {
		return err
	}
	data, err := c.Run(ctx, panelChecks+"echo ready", nil, 1024)
	if err != nil {
		return err
	}
	if result := strings.TrimSpace(string(data)); result != "ready" {
		return panelFailure(result)
	}
	return nil
}

func installPanel(ctx context.Context, c remote, arch string) error {
	digest, ok := panelSHA[arch]
	if !ok {
		return errors.New("Для этой архитектуры нет проверенного пакета AWG Manager.")
	}
	if err := checkPanelReady(ctx, c, &Result{}); err != nil {
		return err
	}
	name := "awg-manager_2.19.25_" + arch + "-kn.ipk"
	const base = "https://github.com/hoaxisr/awg-manager/releases/download/v2.19.25/"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+name, nil)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 2 * time.Minute, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		h := strings.ToLower(r.URL.Hostname())
		if len(via) > 5 || r.URL.Scheme != "https" || (h != "github.com" && !strings.HasSuffix(h, ".githubusercontent.com")) {
			return errors.New("unexpected package redirect")
		}
		return nil
	}}
	resp, err := client.Do(req)
	if err != nil {
		return errors.New("Не удалось загрузить официальный пакет AWG Manager с GitHub.")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Сервер пакетов вернул HTTP %d.", resp.StatusCode)
	}
	const limit = 24 << 20
	pkg, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil || len(pkg) > limit {
		return errors.New("Получен неполный или слишком большой пакет.")
	}
	sum := sha256.Sum256(pkg)
	if hex.EncodeToString(sum[:]) != digest {
		return panelFailure("hash")
	}
	// Fresh install only. Owner data directories are never adopted or replaced.
	script := panelChecks + `
lock=/opt/tmp/keenetic-vpn-setup.install
mkdir "$lock" || msg lock
seed=
cleanup() {
  rm -f "$lock/PKGNAME" "$lock/seed"
  rmdir "$lock" 2>/dev/null || :
}
trap cleanup EXIT
trap 'exit 1' INT TERM HUP
cat >"$lock/PKGNAME" || msg hash
test "$(sha256sum "$lock/PKGNAME" | cut -d' ' -f1)" = PKGHASH || msg hash
deps=$(/opt/bin/opkg list-installed)
for dep in iptables ip-full wireguard-tools conntrack; do
  if ! printf '%s\n' "$deps" | grep -q "^$dep - "; then
    /opt/bin/opkg update >/dev/null 2>&1 || msg feeds
    break
  fi
done
printf '%s\n' '{"schemaVersion":41,"authEnabled":true,"usageLevel":"advanced","server":{"port":2222,"interface":"lo","interfaces":["lo"]},"updates":{"checkEnabled":false,"autoInstallEnabled":false,"statsEnabled":false},"createNDMSProxyForSingbox":true,"singboxRouter":{"enabled":false}}' >"$lock/seed" || msg entware
mkdir /opt/etc/awg-manager || msg occupied
cp "$lock/seed" /opt/etc/awg-manager/settings.json || msg entware
if ! /opt/bin/opkg install "$lock/PKGNAME" >/dev/null 2>&1; then
  if test ! -e /opt/bin/awg-manager && cmp -s "$lock/seed" /opt/etc/awg-manager/settings.json; then
    rm -f /opt/etc/awg-manager/settings.json
    rmdir /opt/etc/awg-manager 2>/dev/null || :
  fi
  msg opkg
fi
/opt/bin/opkg list-installed | grep -q '^awg-manager - 2\.19\.25$' || msg opkg
echo installed`
	script = strings.NewReplacer("PKGNAME", name, "PKGHASH", digest).Replace(script)
	data, err := c.Run(ctx, script, pkg, 2048)
	if err != nil {
		return err
	}
	if result := strings.TrimSpace(string(data)); result != "installed" {
		return panelFailure(result)
	}
	return nil
}
