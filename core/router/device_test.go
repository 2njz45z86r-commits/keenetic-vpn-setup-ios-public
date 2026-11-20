package router

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAttachOnlySSHClientAndVerifyReplay(t *testing.T) {
	const ip, mac, proxy = "192.168.88.12", "02:00:00:00:00:12", "Proxy4"
	devs := []nativeDevice{{IP: ip, MAC: mac, Active: true}, {IP: "192.168.88.11", MAC: "02:00:00:00:00:11", Active: true, Policy: "Policy1"}}
	policies := []nativePolicy{{Name: "Policy1", Description: "Existing"}}
	writes := 0
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var v json.RawMessage
		out := any(map[string]bool{"ok": true})
		if r.Method == "POST" {
			writes++
			if err := json.NewDecoder(r.Body).Decode(&v); err != nil {
				t.Error(err)
			}
		}
		switch r.URL.Path {
		case policyAPI + "/devices":
			out = devs
		case policyAPI:
			out = policies
		case policyAPI + "/create":
			var input struct{ Description string }
			_ = json.Unmarshal(v, &input)
			policies = append(policies, nativePolicy{Name: "Policy2", Description: input.Description})
			out = policies[1]
		case policyAPI + "/permit":
			var input struct{ Name, Interface string }
			_ = json.Unmarshal(v, &input)
			if input.Name != "Policy2" || input.Interface != proxy {
				t.Error("unexpected route change")
			}
			policies[1].Interfaces = append(policies[1].Interfaces, struct {
				Name   string
				Denied bool
			}{Name: proxy})
		case policyAPI + "/standalone":
			var input struct {
				Name    string
				Enabled bool
			}
			_ = json.Unmarshal(v, &input)
			if input.Name != "Policy2" || !input.Enabled {
				t.Error("incorrect standalone target")
			}
			policies[1].Standalone = true
		case policyAPI + "/assign":
			var input struct{ MAC, Policy string }
			_ = json.Unmarshal(v, &input)
			if input.MAC != mac || input.Policy != "Policy2" {
				t.Error("incorrect device")
			}
			devs[0].Policy = input.Policy
		default:
			t.Errorf("unexpected request %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "data": out})
	}))
	defer s.Close()
	m := &management{client: s.Client(), base: s.URL}
	for i := 0; i < 2; i++ {
		name, err := attach(context.Background(), m, ip, proxy)
		if err != nil || name != "Policy2" {
			t.Fatalf("assignment: %s %v", name, err)
		}
	}
	if writes != 4 || devs[1].Policy != "Policy1" {
		t.Fatal("replay added changes or another device moved")
	}
}
