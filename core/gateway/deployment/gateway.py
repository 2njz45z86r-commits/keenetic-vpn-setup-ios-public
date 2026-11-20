"""Private subscription updater and authenticated SOCKS5 ingress for Mihomo."""
import asyncio
import base64
import contextlib
import hashlib
import hmac
import http.client
import ipaddress
import json
import os
from pathlib import Path
import socket
import struct
import sys
import urllib.parse
import urllib.request

MAX = 2 << 20
SCHEMES = {"vless", "vmess", "ss", "ssr", "trojan", "hysteria", "hysteria2",
           "hy2", "tuic", "anytls", "mierus"}
OK = b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00"
FAIL = b"\x05\x01" + OK[2:]


def normalize(data):
    if len(data) > MAX:
        raise ValueError("feed too large")
    if b"://" not in data:
        flat = b"".join(data.split())
        data = base64.b64decode(flat + b"=" * (-len(flat) % 4), altchars=b"-_", validate=True)
    links, seen = [], set()
    for line in data.decode("utf-8-sig").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        scheme, sep, payload = line.partition("://")
        if not sep or scheme.lower() not in SCHEMES or not payload or payload.startswith("#"):
            raise ValueError("feed requires supported share links")
        if any(ord(c) < 32 or ord(c) == 127 for c in line):
            raise ValueError("control character in link")
        identity = line.partition("#")[0]
        if identity not in seen:
            links.append(line)
            seen.add(identity)
    if len(links) < 2:
        raise ValueError("at least two distinct endpoints required")
    return ("\n".join(links) + "\n").encode()


class ProviderRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        old, new = urllib.parse.urlsplit(req.full_url), urllib.parse.urlsplit(newurl)
        if new.scheme not in {"http", "https"} or (old.scheme == "https" and new.scheme != "https"):
            raise ValueError("invalid provider redirect")
        new_request = super().redirect_request(req, fp, code, msg, headers, newurl)
        if (old.scheme, old.hostname, old.port) != (new.scheme, new.hostname, new.port):
            for header, _ in new_request.header_items():
                if header.lower() in {"x-hwid", "authorization", "cookie", "user-agent"}:
                    new_request.remove_header(header)
        return new_request


def fetch(cfg):
    headers = {"User-Agent": "Keenetic-LAN-Gateway/1", **cfg.get("headers", {})}
    req = urllib.request.Request(cfg["url"], headers=headers)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), ProviderRedirect())
    with opener.open(req, timeout=20) as response:
        return normalize(response.read(MAX + 1))


def atomic(path, data):
    temp = path.with_suffix(".new")
    temp.write_bytes(data)
    os.replace(temp, path)


async def address(reader, kind):
    if kind == 1:
        return await reader.readexactly(4)
    if kind == 4:
        return await reader.readexactly(16)
    if kind == 3:
        length = await reader.readexactly(1)
        if length == b"\x00":
            raise ValueError("empty domain")
        return length + await reader.readexactly(length[0])
    raise ValueError("unknown address family")


async def copy(reader, writer):
    while data := await reader.read(65536):
        writer.write(data)
        await writer.drain()
    if writer.can_write_eof():
        with contextlib.suppress(OSError):
            writer.write_eof()


class ReturnUDP(asyncio.DatagramProtocol):
    def __init__(self, relay):
        self.relay = relay

    def datagram_received(self, data, _):
        if self.relay.client:
            self.relay.gateway.udp.sendto(data, self.relay.client)


class Association:
    def __init__(self, gateway, peer, client_port):
        self.gateway = gateway
        self.peer = peer
        self.client = (peer, client_port) if client_port else None
        self.channel = None

    async def start(self):
        loop = asyncio.get_running_loop()
        self.channel, _ = await loop.create_datagram_endpoint(
            lambda: ReturnUDP(self), remote_addr=("127.0.0.1", self.gateway.engine_port))

    def close(self):
        if self.channel:
            self.channel.close()


class IngressUDP(asyncio.DatagramProtocol):
    def __init__(self, gateway):
        self.gateway = gateway

    def datagram_received(self, data, peer):
        if not self.gateway.ready or len(data) < 8 or data[:3] != b"\x00\x00\x00":
            return
        active = self.gateway.associations.get(peer[0], ())
        selected = next((a for a in active if a.client == peer), None)
        if selected is None:
            selected = next((a for a in active if a.client is None), None)
            if selected:
                selected.client = peer
        if selected and selected.channel:
            selected.channel.sendto(data)


class Gateway:
    def __init__(self, cfg, engine_port):
        self.password = cfg["password"].encode()
        self.udp_reply = b"\x05\x00\x00\x01" + socket.inet_aton(cfg["lan"]) + struct.pack("!H", cfg["port"])
        self.engine_port = engine_port
        self.associations = {}
        self.udp = None
        self.ready = False

    async def accept(self, reader, writer):
        upstream, assoc = None, None
        try:
            async with asyncio.timeout(15):
                version, count = await reader.readexactly(2)
                methods = await reader.readexactly(count)
                if version != 5 or 2 not in methods:
                    writer.write(b"\x05\xff")
                    return
                writer.write(b"\x05\x02")
                version, length = await reader.readexactly(2)
                name = await reader.readexactly(length)
                length = (await reader.readexactly(1))[0]
                password = await reader.readexactly(length)
                if version != 1 or name not in (b"keenetic", b"keenetic-cable") or not hmac.compare_digest(password, self.password):
                    writer.write(b"\x01\x01")
                    return
                writer.write(b"\x01\x00")
                ver, command, reserved, kind = await reader.readexactly(4)
                addr = await address(reader, kind)
                port = await reader.readexactly(2)
                if ver != 5 or reserved or not self.ready:
                    writer.write(FAIL)
                    return
                if command == 3:
                    peer = writer.get_extra_info("peername")[0]
                    if kind not in (1, 4) or (int.from_bytes(addr) and str(ipaddress.ip_address(addr)) != peer):
                        writer.write(FAIL)
                        return
                    active = self.associations.setdefault(peer, [])
                    client_port = int.from_bytes(port)
                    # With an unspecified client port at most one association may be
                    # waiting for its first datagram from the authenticated peer.
                    if len(active) >= 128 or any(a.client == ((peer, client_port) if client_port else None) for a in active):
                        writer.write(FAIL)
                        return
                    assoc = Association(self, peer, client_port)
                    active.append(assoc)
                    await assoc.start()
                    if name == b"keenetic-cable":
                        inside_ip, inside_port = writer.get_extra_info("sockname")[:2]
                        writer.write(b"\x05\x00\x00\x01" + socket.inet_aton(inside_ip) + struct.pack("!H", inside_port))
                    else:
                        writer.write(self.udp_reply)
                elif command == 1:
                    server, upstream = await asyncio.open_connection("127.0.0.1", self.engine_port)
                    upstream.write(b"\x05\x01\x00")
                    if await server.readexactly(2) != b"\x05\x00":
                        raise OSError("engine handshake")
                    upstream.write(bytes((5, 1, 0, kind)) + addr + port)
                    reply = await server.readexactly(4)
                    end = await address(server, reply[3]) + await server.readexactly(2)
                    writer.write(reply + end)
                    if reply[1]:
                        return
                else:
                    writer.write(b"\x05\x07" + OK[2:])
                    return
                await writer.drain()
            if assoc:
                await reader.read(1)
            else:
                async with asyncio.TaskGroup() as pair:
                    pair.create_task(copy(reader, upstream))
                    pair.create_task(copy(server, writer))
        except (Exception, asyncio.CancelledError):
            pass
        finally:
            if assoc:
                active = self.associations.get(assoc.peer, [])
                if assoc in active:
                    active.remove(assoc)
                if not active:
                    self.associations.pop(assoc.peer, None)
                assoc.close()
            if upstream:
                upstream.close()
            writer.close()


def control(controller, secret, path, method="GET"):
    req = urllib.request.Request("http://" + controller + path, method=method,
                                 headers={"Authorization": "Bearer " + secret})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(req, timeout=5) as response:
        return response.read(4 << 20)


async def serve(private=Path("/private"), state=Path("/state"), binary="/usr/local/bin/mihomo",
                host="0.0.0.0", port=1080):
    cfg = json.loads((private / "source.json").read_bytes())
    template = private / "config.yaml"
    engine = json.loads(template.read_bytes())
    controller, secret = engine["external-controller"], engine["secret"]
    identity = json.dumps([cfg.get("url"), cfg.get("headers")], sort_keys=True).encode()
    store = state / "providers"
    store.mkdir(mode=0o700, parents=True, exist_ok=True)
    live = store / "servers.txt"
    cache = state / ("good-" + hashlib.sha256(identity).hexdigest())
    status = state / "status.json"
    status.unlink(missing_ok=True)
    # Only a source's last confirmed member set may be used during an outage.
    if cfg.get("url"):
        try:
            candidate = normalize(cache.read_bytes())
        except (OSError, ValueError):
            candidate = await asyncio.to_thread(fetch, cfg)
    else:
        candidate = normalize((private / "servers.txt").read_bytes())
    atomic(live, candidate)
    proc = await asyncio.create_subprocess_exec(binary, "-d", str(state), "-f", str(template),
                                                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
    gateway = Gateway(cfg, engine["socks-port"])
    server = None
    ctl = lambda path, method="GET": asyncio.to_thread(control, controller, secret, path, method)

    async def members():
        info = json.loads(await ctl("/proxies/AUTO"))
        active = set(info.get("all", [])) - {"DIRECT", "REJECT", "COMPATIBLE"}
        if info.get("type", "").lower() != "urltest" or len(active) < 2:
            raise ValueError("not enough native members")
        return len(active)

    try:
        for _ in range(50):
            if proc.returncode is not None:
                raise RuntimeError("engine stopped")
            try:
                count = await members()
                break
            except (OSError, ValueError):
                await asyncio.sleep(0.2)
        else:
            raise RuntimeError("engine could not confirm two members")
        last_good = candidate
        if cfg.get("url"):
            atomic(cache, last_good)
        gateway.udp, _ = await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: IngressUDP(gateway), local_addr=(host, port))
        server = await asyncio.start_server(gateway.accept, host, port)
        gateway.ready = True
        atomic(status, json.dumps({"members": count}).encode())
        print(f"Gateway ready. VPN profiles: {count}.", flush=True)
        # A cached provider remains usable while the next fetch is in progress.
        next_refresh = asyncio.get_running_loop().time() + (2 if cfg.get("url") else 3600)
        while proc.returncode is None:
            await asyncio.sleep(1)
            if not cfg.get("url") or asyncio.get_running_loop().time() < next_refresh:
                continue
            next_refresh = asyncio.get_running_loop().time() + 3600
            try:
                candidate = await asyncio.to_thread(fetch, cfg)
                if candidate == last_good:
                    continue
                gateway.ready = False
                status.unlink(missing_ok=True)
                atomic(live, candidate)
                await ctl("/providers/proxies/subscription", "PUT")
                count = await members()
                atomic(cache, candidate)
                last_good = candidate
            except (OSError, ValueError, http.client.HTTPException):
                print("Subscription update unavailable. Keeping the last verified list.", flush=True)
                if not gateway.ready:
                    atomic(live, last_good)
                    await ctl("/providers/proxies/subscription", "PUT")
                    count = await members()
            gateway.ready = True
            atomic(status, json.dumps({"members": count}).encode())
        raise RuntimeError("engine stopped")
    finally:
        gateway.ready = False
        status.unlink(missing_ok=True)
        if server:
            server.close()
            await server.wait_closed()
        if gateway.udp:
            gateway.udp.close()
        if proc.returncode is None:
            with contextlib.suppress(ProcessLookupError):
                proc.terminate()
            await proc.wait()


if __name__ == "__main__":
    os.umask(0o077)
    if sys.argv[1:] == ["status"]:
        try:
            count = json.loads(Path("/state/status.json").read_bytes())["members"]
            if count >= 2:
                print(f"Ready. VPN profiles: {count}.")
                sys.exit(0)
        except (OSError, ValueError, KeyError):
            pass
        sys.exit(1)
    try:
        asyncio.run(serve())
    except KeyboardInterrupt:
        pass
    except Exception:
        print("Gateway unavailable. Check the provider link, supported profiles and free port.", file=sys.stderr)
        sys.exit(1)
