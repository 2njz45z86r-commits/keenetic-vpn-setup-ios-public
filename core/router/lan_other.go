//go:build !android

package router

import "net"

func configureRouterDialer(_ *net.Dialer) {}
