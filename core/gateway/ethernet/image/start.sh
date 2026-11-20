#!/bin/sh
# This entry point must run inside the dedicated cable container.
set -eu
test -f /run/keenetic-cable-config.json
test -c /dev/net/tun

down=$(ip -4 -o address show | awk '$4 == "192.168.247.1/30" {print $2}')
down=${down%%@*}
case "$down" in
  ''|*[!a-zA-Z0-9_.-]*) echo 'Dedicated /30 interface is missing.' >&2; exit 1 ;;
esac

# Docker only attaches this sidecar to two internal networks. Neither can
# install a default route, even before the rules are set up on restart.
iptables -w -P FORWARD DROP
iptables -w -F FORWARD
iptables -w -A FORWARD -i "$down" -s 192.168.247.2/32 -o kvg-tun -j ACCEPT
iptables -w -A FORWARD -i kvg-tun -o "$down" -d 192.168.247.2/32 -j ACCEPT
iptables -w -C INPUT -i "$down" -j DROP 2>/dev/null || iptables -w -I INPUT 1 -i "$down" -j DROP
ip -4 rule del priority 1000 iif "$down" lookup 247 2>/dev/null || true
ip -4 route flush table 247 2>/dev/null || true
ip -4 rule add priority 1000 iif "$down" lookup 247
ip -4 route add blackhole default metric 32760 table 247

# The SOCKS server shares the directly connected Compose bridge. A default
# route in the main table would only create a second path to the internet.
test -z "$(ip -4 route show default table main)" || { echo 'Unexpected default route in cable container.' >&2; exit 1; }
sing-box check -c /run/keenetic-cable-config.json
sing-box run -c /run/keenetic-cable-config.json &
worker=$!
cleanup() {
  ip -4 route del default dev kvg-tun table 247 2>/dev/null || true
  kill "$worker" 2>/dev/null || true
  wait "$worker" 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 0' TERM INT
tries=0
until ip link show dev kvg-tun >/dev/null 2>&1; do
  kill -0 "$worker" 2>/dev/null && test "$tries" -lt 30 || exit 1
  tries=$((tries + 1))
  sleep 1
done
ip -4 route add default dev kvg-tun metric 10 table 247
echo 'Dedicated IPv4 WAN link ready.'
wait "$worker"
