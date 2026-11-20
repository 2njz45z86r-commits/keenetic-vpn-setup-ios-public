package router

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestSSHCredentialDeliveredOnlyAfterPin(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	var attempts atomic.Int32
	srv := &ssh.ServerConfig{PasswordCallback: func(m ssh.ConnMetadata, v []byte) (*ssh.Permissions, error) {
		attempts.Add(1)
		if m.User() != "entware-test" || string(v) != "synthetic-password" {
			return nil, errors.New("incorrect fixture credentials")
		}
		return nil, nil
	}}
	srv.AddHostKey(signer)
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go func() {
		for {
			raw, e := l.Accept()
			if e != nil {
				return
			}
			go func() {
				defer raw.Close()
				c, ch, req, e := ssh.NewServerConn(raw, srv)
				if e != nil {
					return
				}
				defer c.Close()
				go ssh.DiscardRequests(req)
				for s := range ch {
					s.Reject(ssh.Prohibited, "fixture")
				}
			}()
		}
	}()
	fingerprint := ssh.FingerprintSHA256(signer.PublicKey())
	for i, f := range []string{"", "SHA256:invalid-key", fingerprint} {
		conn, e := (&net.Dialer{}).DialContext(ctx, "tcp", l.Addr().String())
		if e != nil {
			t.Fatal(e)
		}
		cli, observed, e := handshake(ctx, conn, "127.0.0.1", l.Addr().String(), "entware-test", Credentials{Password: "synthetic-password", Fingerprint: f})
		if observed != fingerprint {
			t.Fatal("incorrect peer fingerprint")
		}
		switch i {
		case 0:
			if !errors.Is(e, ErrTrustRequired) || attempts.Load() != 0 {
				t.Fatal("credentials sent before consent")
			}
		case 1:
			if e == nil || attempts.Load() != 0 {
				t.Fatal("changed host key accepted")
			}
		case 2:
			if e != nil || attempts.Load() != 1 {
				t.Fatal("pinned authentication failed", e)
			}
			cli.client.Close()
		}
	}
}
