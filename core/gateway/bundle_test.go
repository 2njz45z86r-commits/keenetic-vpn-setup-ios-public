package gateway

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"
)

func openBundle(t *testing.T, req Request) map[string]string {
	t.Helper()
	data, err := Bundle(req)
	if err != nil {
		t.Fatal(err)
	}
	z, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	files := make(map[string]string)
	for _, f := range z.File {
		r, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(r)
		r.Close()
		if err != nil {
			t.Fatal(err)
		}
		files[f.Name] = string(b)
	}
	return files
}

func TestPrivateGatewayBundle(t *testing.T) {
	req := Request{LANAddress: "192.168.20.50", Port: 12080, Subscription: "incy://import/https%3A%2F%2Fprovider.example%2Fs%2Ftoken%3Fv%3D1", HWID: "owner-slot"}
	files := openBundle(t, req)
	var cfg settings
	if err := json.Unmarshal([]byte(files["config/source.json"]), &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.URL != "https://provider.example/s/token?v=1" || cfg.Headers["X-HWID"] != "owner-slot" || len(cfg.Password) != 48 {
		t.Fatal("private input mismatch")
	}
	for _, path := range []string{"service/Dockerfile", "service/gateway.py", "compose.yaml"} {
		if files[path] == "" || strings.Contains(files[path], cfg.Password) || strings.Contains(files[path], "owner-slot") || strings.Contains(files[path], "provider.example") {
			t.Fatalf("bad build context or compose %s", path)
		}
	}
	if strings.Count(files["compose.yaml"], "192.168.20.50:12080:1080/") != 2 || strings.Contains(files["compose.yaml"], "9090") {
		t.Fatal("wrong publication")
	}
	if !strings.Contains(files["config/config.yaml"], `"empty-fallback": "REJECT"`) {
		t.Fatal("missing fail closed setting")
	}
	if !strings.Contains(files["ethernet/client.json"], cfg.Password) || files["ethernet/image/start.sh"] == "" {
		t.Fatal("missing Ethernet template or gateway credentials")
	}
	if strings.Contains(files["ethernet/image/start.sh"]+files["ethernet/image/Dockerfile"], cfg.Password) {
		t.Fatal("private Ethernet password entered Docker build context")
	}
	again := openBundle(t, req)
	if files["config/source.json"] == again["config/source.json"] {
		t.Fatal("shared credentials")
	}
}

func TestWholeInlineGatewayFeed(t *testing.T) {
	for _, count := range []int{10, 30} {
		lines := make([]string, count)
		for i := range lines {
			lines[i] = fmt.Sprintf("trojan://fixture@node%d.example:443#n%d", i, i)
		}
		actual := strings.Join(lines, "\n") + "\n"
		for _, feed := range []string{actual, base64.RawURLEncoding.EncodeToString([]byte(actual))} {
			files := openBundle(t, Request{LANAddress: "10.2.3.4", Subscription: feed})
			if files["config/servers.txt"] != actual {
				t.Errorf("%d member list changed", count)
			}
		}
	}
}

func TestGatewayInputErrors(t *testing.T) {
	valid := Request{LANAddress: "192.168.0.50", Subscription: "https://provider.example/SENSITIVE"}
	for _, update := range []func(*Request){
		func(r *Request) { r.LANAddress = "0.0.0.0" }, func(r *Request) { r.LANAddress = "8.8.8.8" }, func(r *Request) { r.Port = 65536 },
		func(r *Request) { r.UserAgent = "Bad\r\nX: SENSITIVE" }, func(r *Request) { r.Subscription = "happ://crypt4/SENSITIVE" },
		func(r *Request) { r.Subscription = "vless://u@a:443#one\nvless://u@a:443#renamed" },
		func(r *Request) { r.Subscription = "proxies:\n- {type: direct}" },
	} {
		req := valid
		update(&req)
		b, err := Bundle(req)
		if err == nil || len(b) != 0 || strings.Contains(err.Error(), "SENSITIVE") {
			t.Fatalf("unexpected error or exposure: %v", err)
		}
	}
}
