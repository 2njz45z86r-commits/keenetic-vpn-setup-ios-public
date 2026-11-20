package router

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestPackageArchitecture(t *testing.T) {
	for _, arch := range []string{"mips-3.4", "mipsel-3.4", "aarch64-3.10"} {
		for _, suffix := range []string{"", "-kn", "_kn", "_kn2", "_kn-1.2", "_kn_2"} {
			got, err := packageArchitecture("arch all 100\narch " + arch + suffix + " 200")
			if err != nil || got != arch {
				t.Errorf("%s%s: got %q, %v", arch, suffix, got, err)
			}
		}
	}
	got, err := packageArchitecture("arch aarch64-3.10 150\narch aarch64-3.10_kn 200")
	if err != nil || got != "aarch64-3.10" {
		t.Fatalf("base and vendor aliases: %q, %v", got, err)
	}
	for _, output := range []string{
		"arch all 100", "arch x86_64 150", "arch mips-3.4_knonsense 200",
		"arch mips-3.4 150\narch aarch64-3.10 151", "arch mips-3.4_kn 10\narch x86_64 5",
		"(config)> unknown command",
	} {
		if _, err := packageArchitecture(output); err == nil {
			t.Errorf("accepted ambiguous or invalid output %q", output)
		}
	}
	if _, err := packageArchitecture("(config)>"); !errors.Is(err, errEntwareShell) {
		t.Fatal("expected Entware SSH guidance for the native CLI")
	}
}

type readinessRemote struct {
	t               *testing.T
	version, result string
	calls           int
}

func (f *readinessRemote) Run(_ context.Context, command string, input []byte, _ int) ([]byte, error) {
	f.t.Helper()
	if input != nil {
		f.t.Fatal("readiness check uploaded bytes")
	}
	f.calls++
	switch command {
	case "/bin/ndmc -c 'show version'":
		return []byte(f.version), nil
	case panelChecks + "echo ready":
		return []byte(f.result), nil
	default:
		f.t.Fatalf("unexpected command %q", command)
		return nil, nil
	}
}

func TestRouterReadiness(t *testing.T) {
	const version = "\x1b[K\n release: 5.02.B.4.0-0\n ndw:\n components: base,ip6,pro\n    xy,wireg\n   uard,opkg\n ndw4:\n   release: nested\n model: Ultra (KN-1810)\n\x1b[K"
	r := &Result{}
	f := &readinessRemote{t: t, version: version, result: "ready\n"}
	if err := checkPanelReady(context.Background(), f, r); err != nil || r.Model != "Ultra (KN-1810)" || r.Firmware != "5.02.B.4.0-0" || f.calls != 2 {
		t.Fatalf("ready %#v, calls=%d, err=%v", r, f.calls, err)
	}
	for _, tc := range []struct {
		version, result, hint string
		expectedCalls         int
	}{
		{"components: proxy-helper,wireguard", "ready", "Клиент прокси", 1},
		{"components: base,proxy", "ready", "WireGuard", 1},
		{"release: 5.2", "ready", "список", 1},
		{version, "space", "96 МиБ", 2},
		{version, "occupied", "предыдущей установки", 2},
		{version, "port", "2222", 2},
	} {
		f := &readinessRemote{t: t, version: tc.version, result: tc.result}
		err := checkPanelReady(context.Background(), f, &Result{})
		if err == nil || !strings.Contains(err.Error(), tc.hint) || f.calls != tc.expectedCalls {
			t.Errorf("expected %q and %d calls, got %v and %d", tc.hint, tc.expectedCalls, err, f.calls)
		}
	}
}
