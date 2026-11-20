#!/usr/bin/env bash
set -euo pipefail
umask 077
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
state=ethernet/.dedicated-interface
base=(docker compose -f compose.yaml)
both=(docker compose -f compose.yaml -f ethernet/compose.yaml)
die() { printf '%s\n' "$*" >&2; exit 1; }
action=${1-}
[[ "$(uname -s)" == Linux ]] || die 'This optional mode requires native Linux with local rootful Docker Engine.'
if [[ "$action" == "up" ]]; then
  [[ $# == 2 ]] || die 'Usage: bash ethernet/setup.sh up INTERFACE'
  nic=$2
else
  [[ $# == 1 && ( "$action" == "down" || "$action" == "status" ) ]] || die 'Usage: bash ethernet/setup.sh {up INTERFACE|status|down}'
  [[ -f "$state" ]] || die 'No cable installation recorded in this project.'
  IFS= read -r nic < "$state"
fi
[[ "$nic" =~ ^[a-zA-Z0-9][a-zA-Z0-9_-]{0,14}$ && "$nic" != lo ]] || die 'Expected a dedicated physical Ethernet interface.'
export KEENETIC_ETHERNET_NIC="$nic"
# Host checks below must inspect the same machine as the Docker daemon.
endpoint=${DOCKER_HOST:-$(docker context inspect --format '{{.Endpoints.docker.Host}}')}
[[ "$endpoint" == unix://* ]] || die 'Use a local Unix-socket Docker context on the Linux gateway.'
security=$(docker info --format '{{json .SecurityOptions}}')
[[ "$security" != *rootless* ]] || die 'The cable mode requires rootful Docker Engine.'
exec 9>ethernet/.cable-setup.lock
flock -n 9 || die 'Another cable setup operation is running.'
case "$action" in
  status)
    "${both[@]}" ps ethernet-wan
    "${both[@]}" exec -T ethernet-wan sh -ec 'test "$(cat /proc/sys/net/ipv4/ip_forward)" = 1; ip -4 route show table 247; ip -4 rule list | grep "lookup 247"'
    "${base[@]}" exec -T gateway python -B /app/gateway.py status
    ;;
  down)
    # Obtain the exact Compose project name from the base configuration.
    project=$("${base[@]}" config --format json | python3 -c 'import json,sys; print(json.load(sys.stdin)["name"])')
    "${both[@]}" rm -sf ethernet-wan
    "${base[@]}" up -d --no-deps gateway
    mapfile -t ids < <(docker network ls -q --filter "label=com.docker.compose.project=$project" --filter 'label=com.docker.compose.network=wan_cable')
    for id in "${ids[@]}"; do
      [[ "$(docker network inspect --format '{{index .Options "parent"}}' "$id")" == "$nic" ]] || die 'Network owner or parent mismatch; inspect it before cleanup.'
      docker network rm "$id" >/dev/null
    done
    mapfile -t bus_ids < <(docker network ls -q --filter "label=com.docker.compose.project=$project" --filter 'label=com.docker.compose.network=cable_bus')
    for id in "${bus_ids[@]}"; do docker network rm "$id" >/dev/null; done
    rm -f -- "$state"
    printf '%s\n' 'Cable gateway removed. Restore the original WAN cable and settings on the router.'
    ;;
  up)
    if [[ -e "$state" && "$(<"$state")" != "$nic" ]]; then die 'Use down before changing the dedicated interface.'; fi
    [[ -d "/sys/class/net/$nic/device" && ! -d "/sys/class/net/$nic/wireless" ]] || die 'Choose a separate physical Ethernet NIC, including a USB Ethernet adapter.'
    [[ "$(<"/sys/class/net/$nic/type")" == 1 && ! -L "/sys/class/net/$nic/master" ]] || die 'This interface belongs to a bridge/bond or is not Ethernet.'
    [[ -c /dev/net/tun ]] || die 'Linux TUN (/dev/net/tun) is required.'
    ip -o link show up dev "$nic" | grep -q . || die 'Set this dedicated Ethernet interface administratively up before running setup.'
    [[ -z "$(ip -o -4 addr show dev "$nic")" && -z "$(ip -o -6 addr show dev "$nic" scope global)" ]] || die 'Dedicated interface must have no IPv4 or global IPv6 addresses on the host.'
    [[ -z "$(ip -4 route list table all dev "$nic")" && -z "$(ip -6 route show default dev "$nic")" ]] || die 'The host already uses this interface for routing.'
    ip -j -4 route show table all | python3 -c '
import ipaddress, json, sys
transit = ipaddress.ip_network("192.168.247.0/30")
for route in json.load(sys.stdin):
    dst = route.get("dst", "default")
    if dst not in ("default", "0.0.0.0/0") and ipaddress.ip_network(dst, strict=False).overlaps(transit):
        sys.exit("The dedicated /30 overlaps an existing host route.")
'
    "${base[@]}" exec -T gateway python -B /app/gateway.py status
    "${both[@]}" config -q
    # Record our parent before creating anything, so down works after an
    # interrupted build or a failed health check.
    printf '%s\n' "$nic" > "$state"
    "${both[@]}" up --build --detach --wait --wait-timeout 90 gateway ethernet-wan
    printf '%s\n' 'Cable service is running. See ethernet/README.md before changing the router WAN.'
    ;;
esac
