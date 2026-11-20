package router

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLinks(t *testing.T) {
	want := "https://unit.invalid/sub/t?key=a%2Fb+c"
	for _, s := range []string{want, "happ://add/" + want, "incy://import/https%3A%2F%2Funit.invalid%2Fsub%2Ft%3Fkey%3Da%252Fb%2Bc", "happ://" + want} {
		x, e := parseSource(s)
		if e != nil || x.url != want {
			t.Errorf("wrapper changed URL: %v", e)
		}
	}
	bundle := "vless://00000000-1111-4111-8111-000000000001@a.invalid:443#A\nvless://00000000-1111-4111-8111-000000000002@b.invalid:443#B"
	for _, s := range []string{bundle, base64.StdEncoding.EncodeToString([]byte(bundle)), base64.RawURLEncoding.EncodeToString([]byte(bundle))} {
		x, e := parseSource(s)
		if e != nil || x.count != 2 || x.inline != bundle {
			t.Errorf("multi-profile: %v", e)
		}
	}
	if _, e := parseSource(strings.Split(bundle, "\n")[0]); e == nil {
		t.Error("single node accepted")
	}
	for _, s := range []string{"happ://crypt5/invalid", "file:///tmp/test", "broken://https://bad", "http://", "vless://"} {
		if _, err := parseSource(s); err == nil {
			t.Error("invalid input accepted")
		}
	}
	if x, e := parseSource("happ://crypt4/AAAA"); e != nil || !x.encrypted {
		t.Fatal("native Happ crypt not accepted", e)
	}
}

func TestBoundedReadFrom(t *testing.T) {
	b := &bounded{max: 4}
	_, _ = b.ReadFrom(strings.NewReader("123456"))
	if b.Len() != 4 || !b.overflow {
		t.Fatal("reply cap bypassed")
	}
}

func TestMixedInlineSubscriptions(t *testing.T) {
	for _, size := range []int{10, 30} {
		var lines []string
		for i := 0; i < size; i++ {
			scheme := []string{"trojan", "vless", "hy2"}[i%3]
			id := fmt.Sprintf("00000000-1111-4111-8111-%012d", i)
			lines = append(lines, fmt.Sprintf("%s://%s@n%d.invalid:443#N%d", scheme, id, i, i))
		}
		bundle := strings.Join(lines, "\n")
		for _, input := range []string{bundle, base64.RawURLEncoding.EncodeToString([]byte(bundle)), "# title\r\n" + strings.Join(lines, "\r\n")} {
			s, err := parseSource(input)
			if err != nil || s.count != size || s.inline != bundle {
				t.Fatalf("expected %d mixed links preserved: %v", size, err)
			}
		}
	}
	for _, scheme := range []string{"ss", "hysteria2", "naive+http", "naive+https", "vpn", "mieru", "mierus", "tt"} {
		single := scheme + "://native-parser-payload"
		if _, err := parseSource(single + "\nvless://fixture@host:443"); err != nil {
			t.Errorf("%s feed link was dropped: %v", scheme, err)
		}
	}
	for _, scheme := range []string{"vmess", "socks5", "wireguard"} {
		bundle := "trojan://fixture@a.invalid:443\r\n" + scheme + "://private-material"
		if _, err := parseSource(bundle); err == nil || !strings.Contains(err.Error(), "строке 2") || strings.Contains(err.Error(), "private-material") {
			t.Errorf("expected an actionable redacted error for unsupported %s", scheme)
		}
	}
}

func TestNativeWorkflowAndRetry(t *testing.T) {
	for _, n := range []int{10, 30} {
		t.Run(fmt.Sprintf("%d", n), func(t *testing.T) { testNativeWorkflowAndRetry(t, n) })
	}
}

func testNativeWorkflowAndRetry(t *testing.T, size int) {
	const label = "Дача"
	const sourceURL = "https://provider.invalid/authorized-fixture"
	const selector = "sub-test"
	var saved *subscription
	var routes []string
	var preview, members []member
	var tags []string
	for i := 0; i < size; i++ {
		key := fmt.Sprintf("%08x", i)
		protocol := []string{"vless", "trojan", "shadowsocks", "hysteria2"}[i%4]
		preview = append(preview, member{Key: key, Protocol: protocol})
		tag := selector + "-" + key
		tags = append(tags, tag)
		members = append(members, member{Tag: tag, Protocol: protocol})
	}
	installed, running := false, false
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		routes = append(routes, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		reply := func(x any) { json.NewEncoder(w).Encode(map[string]any{"success": true, "data": x}) }
		st := func() map[string]any {
			payload := map[string]any{"installed": installed, "running": running, "proxyComponent": true, "ndmsProxyEnabled": true, "requiredVersion": "1.15.0-alpha.13-awgm.36"}
			if installed {
				payload["currentVersion"] = "1.15.0-alpha.13-awgm.36"
				payload["currentSha256"] = buildArch["aarch64-3.10"]
				payload["requiredSha256"] = buildArch["aarch64-3.10"]
			}
			return payload
		}
		switch r.URL.Path {
		case "/api/auth/status":
			io.WriteString(w, "{\"authDisabled\":false}")
			return
		case "/api/auth/login":
			var v map[string]string
			json.NewDecoder(r.Body).Decode(&v)
			if v["login"] != "root" || v["password"] != "fixture" || v["method"] != "entware" {
				t.Error("incorrect authentication request")
			}
			http.SetCookie(w, &http.Cookie{Name: "awg_session", Value: "local-test", Path: "/"})
			io.WriteString(w, "{\"success\":true}")
			return
		}
		if v, e := r.Cookie("awg_session"); e != nil || v.Value != "local-test" {
			http.Error(w, "auth", 401)
			return
		}
		switch r.URL.Path {
		case "/api/singbox/status":
			reply(st())
		case "/api/singbox/router/status":
			reply(map[string]bool{"enabled": false})
		case subscriptions:
			if saved != nil {
				reply([]subscription{*saved})
			} else {
				reply([]subscription{})
			}
		case subscriptions + "/preview":
			var payload struct {
				URL     string
				Headers []header
			}
			json.NewDecoder(r.Body).Decode(&payload)
			if payload.URL != sourceURL || len(payload.Headers) != 1 {
				t.Error("missing source or authorized header")
			}
			reply(preview)
		case "/api/singbox/install":
			installed = true
			reply(st())
		case subscriptions + "/create":
			var p struct {
				URL, Label, Mode string
				Enabled          bool
				ExcludedKeys     []string
				URLTest          struct{ IntervalSec, ToleranceMs int }
			}
			json.NewDecoder(r.Body).Decode(&p)
			if p.URL != sourceURL || p.Label != label || !p.Enabled || p.Mode != "urltest" || p.URLTest.IntervalSec != 60 || p.URLTest.ToleranceMs != 50 || len(p.ExcludedKeys) != 0 {
				t.Errorf("wrong subscription configuration")
			}
			if saved != nil {
				t.Error("duplicated existing subscription")
			}
			idx := 2
			saved = &subscription{ID: "only-test", Label: label, URL: p.URL, Mode: p.Mode, Enabled: true, SelectorTag: selector, MemberTags: tags, Members: members, ProxyIndex: &idx, ListenPort: 11000}
			saved.Headers = []header{{"X-HWID", "authorized-fixture"}}
			reply(saved)
		case "/api/singbox/control":
			running = true
			reply(st())
		default:
			t.Errorf("unexpected mutation/route %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer s.Close()
	m := &management{client: s.Client(), base: s.URL}
	m.client.Jar, _ = cookiejar.New(nil)
	if e := m.open(context.Background(), Credentials{Username: "root", Password: "fixture"}); e != nil {
		t.Fatal(e)
	}
	for attempt := 0; attempt < 2; attempt++ {
		r := Result{Architecture: "aarch64-3.10", PanelVersion: "2.19.25"}
		res, e := workflow(context.Background(), m, &r, Options{InstallMissing: true}, source{url: sourceURL}, label, []header{{"X-HWID", "authorized-fixture"}}, func(_ context.Context, i, p int) error {
			if i != 2 || p != 11000 {
				return fmt.Errorf("bad proxy mapping")
			}
			return nil
		}, nil)
		if e != nil || res.Profiles != size || res.Proxy != "Proxy2" || res.Imported != (attempt == 0) || res.InstalledEngine != (attempt == 0) || strings.Contains(res.Message, "отсутствующих") {
			t.Fatalf("result %+v err %v", res, e)
		}
	}
	if strings.Count(strings.Join(routes, " "), subscriptions+"/create") != 1 {
		t.Fatal("create must be idempotent")
	}
}

func TestMaterializedGroupMembership(t *testing.T) {
	group := subscription{Mode: "urltest", Enabled: true, SelectorTag: "sub-group", MemberTags: []string{"first", "second"}, Members: []member{{Tag: "second", Protocol: "trojan"}, {Tag: "first", Protocol: "vless"}}}
	if !automaticGroupVerified(&group) {
		t.Fatal("mixed group with reordered metadata rejected")
	}
	group.Members[1].Tag = "second"
	if automaticGroupVerified(&group) {
		t.Fatal("duplicate member metadata passed")
	}
	group.MemberTags[0] = "second"
	if automaticGroupVerified(&group) {
		t.Fatal("duplicate native tags passed")
	}
}

func TestExistingProxyPreferencePreservedAndErrorPrivacy(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/singbox/status" || r.Method != "GET" {
			t.Error("unexpected API mutation")
		}
		io.WriteString(w, "{\"success\":true,\"data\":{\"installed\":true,\"running\":true,\"proxyComponent\":true,\"ndmsProxyEnabled\":false}}")
	}))
	defer s.Close()
	m := &management{s.Client(), s.URL}
	r := Result{}
	_, err := workflow(context.Background(), m, &r, Options{}, source{url: "https://x.invalid/private-token"}, "sample", nil, nil, nil)
	if err == nil || strings.Contains(err.Error(), "private-token") {
		t.Error("expected sanitized diagnostic")
	}
}
