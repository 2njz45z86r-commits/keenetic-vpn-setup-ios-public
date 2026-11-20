//go:build android

package router

import (
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// Refuse to cross an IPv4 router, also when SELinux hides interface addresses.
func configureRouterDialer(d *net.Dialer) {
	d.Control = func(_, _ string, c syscall.RawConn) error {
		var sockErr error
		err := c.Control(func(fd uintptr) { sockErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TTL, 1) })
		if err != nil {
			return err
		}
		return sockErr
	}
}
