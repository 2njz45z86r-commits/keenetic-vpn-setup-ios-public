package mobile

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestLocalWizardRejectsForeignOriginAndUntrustedRouter(t *testing.T) {
	start, err := Start()
	if err != nil {
		t.Fatal(err)
	}
	defer Stop()
	u, err := url.Parse(start)
	if err != nil {
		t.Fatal(err)
	}
	origin := u.Scheme + "://" + u.Host
	if u.Hostname() != "127.0.0.1" || len(u.Fragment) < 40 {
		t.Fatal("not a private launch URL")
	}
	resp, err := http.Get(origin + "/")
	if err != nil {
		t.Fatal(err)
	}
	html, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(html), "Подключение к роутеру") || strings.Contains(string(html), u.Fragment) {
		t.Fatal("wizard bootstrap or token exposure")
	}
	payload := "{\"Host\":\"192.168.1.1\",\"Port\":222,\"Fingerprint\":\"untrusted\"}"
	for _, tc := range []struct {
		origin, token, path string
		status              int
	}{
		{"https://example.org", u.Fragment, "inspect", 403},
		{origin, "wrong", "inspect", 403},
		{origin, u.Fragment, "apply", 409},
		{origin, u.Fragment, "attach", 409},
		{"https://example.org", u.Fragment, "gateway", 403},
		{origin, "wrong", "gateway", 403},
	} {
		r, _ := http.NewRequest("POST", origin+"/api/"+tc.path, strings.NewReader(payload))
		r.Header.Set("Origin", tc.origin)
		r.Header.Set("Authorization", "Bearer "+tc.token)
		response, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != tc.status {
			t.Fatalf("%s status %d, want %d", tc.path, response.StatusCode, tc.status)
		}
	}
}

func TestExportPrivateGatewayArchiveWithoutRouterLogin(t *testing.T) {
	start, err := Start()
	if err != nil {
		t.Fatal(err)
	}
	defer Stop()
	u, err := url.Parse(start)
	if err != nil {
		t.Fatal(err)
	}
	origin := "http://" + u.Host
	body := `{"LANAddress":"192.168.7.20","Port":1080,"Subscription":"https://example.invalid/subscription"}`
	req, err := http.NewRequest("POST", origin+"/api/gateway", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Origin", origin)
	req.Header.Set("Authorization", "Bearer "+u.Fragment)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var result struct{ Archive []byte }
	if resp.StatusCode != 200 || json.NewDecoder(resp.Body).Decode(&result) != nil {
		t.Fatalf("gateway download HTTP %d", resp.StatusCode)
	}
	bundle, err := zip.NewReader(bytes.NewReader(result.Archive), int64(len(result.Archive)))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"compose.yaml", "README.md"} {
		if _, err := bundle.Open(name); err != nil {
			t.Fatal(err)
		}
	}
}
