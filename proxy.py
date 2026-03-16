#!/usr/bin/env python3
"""
Blind HTTP/HTTPS proxy with custom DNS server support.
Pure Python stdlib — no third-party dependencies.

Usage:
    python proxy.py [--host HOST] [--port PORT] [--dns DNS_SERVER] [--dns-port DNS_PORT]

Examples:
    python proxy.py --dns 1.1.1.1
    python proxy.py --dns 8.8.8.8 --port 8888
    python proxy.py --dns 192.168.1.1 --dns-port 53
"""

import argparse
import socket
import struct
import threading
import logging
import random

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("proxy")

BUFFER = 65536


# ---------------------------------------------------------------------------
# Minimal DNS client (RFC 1035) — stdlib only
# ---------------------------------------------------------------------------

def _encode_name(name: str) -> bytes:
    """Encode a dotted hostname into DNS wire-format labels."""
    out = b""
    for label in name.rstrip(".").split("."):
        encoded = label.encode()
        out += bytes([len(encoded)]) + encoded
    return out + b"\x00"


def _build_query(name: str, qtype: int, txid: int) -> bytes:
    """Build a minimal DNS query packet."""
    header = struct.pack(
        "!HHHHHH",
        txid,   # transaction ID
        0x0100, # flags: standard query, recursion desired
        1,      # QDCOUNT
        0, 0, 0 # ANCOUNT, NSCOUNT, ARCOUNT
    )
    question = _encode_name(name) + struct.pack("!HH", qtype, 1)  # QTYPE, QCLASS=IN
    return header + question


def _decode_name(data: bytes, offset: int):
    """Decode a DNS name from wire format, following pointers. Returns (name, new_offset)."""
    labels = []
    visited = set()
    original_offset = offset
    jumped = False
    final_offset = None

    while True:
        if offset >= len(data):
            break
        length = data[offset]
        if length == 0:
            if not jumped:
                final_offset = offset + 1
            break
        if (length & 0xC0) == 0xC0:
            # Pointer
            if offset + 1 >= len(data):
                break
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                final_offset = offset + 2
            jumped = True
            if pointer in visited:
                break  # loop guard
            visited.add(pointer)
            offset = pointer
        else:
            offset += 1
            labels.append(data[offset:offset + length].decode(errors="replace"))
            offset += length

    if final_offset is None:
        final_offset = offset
    return ".".join(labels), final_offset


def _parse_response(data: bytes, qtype: int) -> str:
    """
    Parse a DNS response and return the first matching IP address string.
    Raises ValueError if no usable record is found.
    """
    if len(data) < 12:
        raise ValueError("Response too short")

    _txid, flags, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", data[:12])
    rcode = flags & 0x0F
    if rcode != 0:
        raise ValueError(f"DNS error rcode={rcode}")
    if ancount == 0:
        raise ValueError("No answers in DNS response")

    offset = 12

    # Skip question section
    for _ in range(qdcount):
        _, offset = _decode_name(data, offset)
        offset += 4  # QTYPE + QCLASS

    # Parse answer records
    for _ in range(ancount):
        _, offset = _decode_name(data, offset)
        if offset + 10 > len(data):
            break
        rtype, _rclass, _ttl, rdlength = struct.unpack("!HHIH", data[offset:offset + 10])
        offset += 10
        rdata = data[offset:offset + rdlength]
        offset += rdlength

        if rtype == 1 and rdlength == 4:    # A record
            return socket.inet_ntop(socket.AF_INET, rdata)
        if rtype == 28 and rdlength == 16:  # AAAA record
            return socket.inet_ntop(socket.AF_INET6, rdata)

    raise ValueError("No usable A/AAAA record found in response")


def _recv_exactly(sock: socket.socket, n: int) -> bytes:
    """Read exactly n bytes from a socket."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise OSError("Connection closed before receiving expected bytes")
        buf += chunk
    return buf


def _dns_tcp(query: bytes, dns_server: str, dns_port: int, timeout: float) -> bytes:
    """Send a DNS query over TCP (RFC 1035 length-prefixed framing)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        sock.connect((dns_server, dns_port))
        framed = struct.pack("!H", len(query)) + query
        sock.sendall(framed)
        length_data = _recv_exactly(sock, 2)
        length = struct.unpack("!H", length_data)[0]
        return _recv_exactly(sock, length)


def dns_resolve(hostname: str, dns_server: str, dns_port: int = 53, timeout: float = 5.0) -> str:
    """
    Resolve a hostname to an IP string using the specified DNS server.
    Bypasses the OS resolver entirely. Tries A then AAAA records.
    Uses UDP with automatic TCP fallback for truncated responses.
    """
    # Already an IP address — pass through unchanged
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(family, hostname)
            return hostname
        except OSError:
            pass

    txid = random.randint(0, 0xFFFF)
    last_exc: Exception = OSError("No query attempted")

    for qtype in (1, 28):  # A, then AAAA
        query = _build_query(hostname, qtype, txid)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                sock.sendto(query, (dns_server, dns_port))
                resp, _ = sock.recvfrom(4096)

            # TC (truncated) flag — retry over TCP
            if len(resp) >= 3 and (resp[2] & 0x02):
                resp = _dns_tcp(query, dns_server, dns_port, timeout)

            ip = _parse_response(resp, qtype)
            log.debug(f"DNS {dns_server}: {hostname} -> {ip}")
            return ip
        except Exception as e:
            last_exc = e
            continue

    raise OSError(f"DNS resolution failed for {hostname!r}: {last_exc}")


# ---------------------------------------------------------------------------
# Relay helpers
# ---------------------------------------------------------------------------

def relay(src: socket.socket, dst: socket.socket) -> None:
    """Forward bytes from src to dst until either side closes or errors."""
    try:
        while True:
            data = src.recv(BUFFER)
            if not data:
                break
            dst.sendall(data)
    except Exception:
        pass
    finally:
        for s in (src, dst):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass


def tunnel(client: socket.socket, remote: socket.socket) -> None:
    """Bidirectional byte relay between two sockets (blocks until both sides close)."""
    t1 = threading.Thread(target=relay, args=(client, remote), daemon=True)
    t2 = threading.Thread(target=relay, args=(remote, client), daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()


# ---------------------------------------------------------------------------
# HTTP parsing
# ---------------------------------------------------------------------------

def recv_headers(sock: socket.socket) -> bytes:
    """Read bytes until we have a complete HTTP header block (ends with \\r\\n\\r\\n)."""
    data = b""
    sock.settimeout(30)
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(BUFFER)
        if not chunk:
            return b""
        data += chunk
    return data


def parse_request(raw: bytes):
    """
    Parse HTTP request line and headers.
    Returns (method, url, version, headers_dict).
    """
    header_block = raw.split(b"\r\n\r\n", 1)[0]
    lines = header_block.decode(errors="replace").split("\r\n")
    parts = lines[0].split(" ", 2)
    if len(parts) != 3:
        raise ValueError(f"Bad request line: {lines[0]!r}")
    method, url, version = parts
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return method, url, version, headers


def host_port_from(url: str, headers: dict, default_port: int = 80):
    """
    Determine the target host and port from the Host header or the request URL.
    """
    host = headers.get("host", "")
    port = default_port

    if host:
        if host.startswith("["):
            # IPv6 literal: [::1] or [::1]:8080
            end = host.find("]")
            if end != -1 and end + 1 < len(host) and host[end + 1] == ":":
                port = int(host[end + 2:])
            host = host[1:end]
        elif ":" in host:
            host, port_str = host.rsplit(":", 1)
            port = int(port_str)
        return host, port

    # Parse from URL
    s = url
    if s.lower().startswith("http://"):
        s = s[7:]
        default_port = 80
    elif s.lower().startswith("https://"):
        s = s[8:]
        default_port = 443

    s = s.split("/", 1)[0].split("?", 1)[0]
    if ":" in s:
        host, port_str = s.rsplit(":", 1)
        port = int(port_str)
    else:
        host = s
        port = default_port

    return host, port


# ---------------------------------------------------------------------------
# Request handlers
# ---------------------------------------------------------------------------

def handle_connect(client: socket.socket, host: str, port: int, dns_server: str, dns_port: int):
    """HTTPS CONNECT: resolve host, open raw TCP connection, then tunnel blindly."""
    try:
        ip = dns_resolve(host, dns_server, dns_port)
    except OSError as e:
        log.warning(f"DNS fail {host}: {e}")
        client.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
        return

    try:
        remote = socket.create_connection((ip, port), timeout=10)
    except OSError as e:
        log.warning(f"Connect fail {ip}:{port}: {e}")
        client.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
        return

    log.info(f"CONNECT {host}:{port} ({ip})")
    client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
    tunnel(client, remote)
    remote.close()


def handle_http(
    client: socket.socket,
    method: str,
    url: str,
    raw: bytes,
    headers: dict,
    dns_server: str,
    dns_port: int,
):
    """Plain HTTP: resolve host, forward raw request bytes, stream response back."""
    try:
        host, port = host_port_from(url, headers, default_port=80)
    except (ValueError, IndexError) as e:
        log.warning(f"Bad URL {url!r}: {e}")
        client.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
        return

    try:
        ip = dns_resolve(host, dns_server, dns_port)
    except OSError as e:
        log.warning(f"DNS fail {host}: {e}")
        client.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
        return

    try:
        remote = socket.create_connection((ip, port), timeout=10)
    except OSError as e:
        log.warning(f"Connect fail {ip}:{port}: {e}")
        client.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
        return

    log.info(f"{method} {url} -> {ip}:{port}")
    try:
        remote.sendall(raw)
        relay(remote, client)
    finally:
        remote.close()


# ---------------------------------------------------------------------------
# Per-connection dispatcher
# ---------------------------------------------------------------------------

def handle_client(client: socket.socket, addr, dns_server: str, dns_port: int):
    try:
        raw = recv_headers(client)
        if not raw:
            return

        method, url, _version, headers = parse_request(raw)

        if method == "CONNECT":
            # url is "host:port"
            if ":" in url:
                host, port_str = url.rsplit(":", 1)
                port = int(port_str)
            else:
                host, port = url, 443
            handle_connect(client, host, port, dns_server, dns_port)
        else:
            handle_http(client, method, url, raw, headers, dns_server, dns_port)

    except Exception as e:
        log.debug(f"Client {addr} error: {e}")
    finally:
        try:
            client.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Server loop
# ---------------------------------------------------------------------------

def run_proxy(listen_host: str, listen_port: int, dns_server: str, dns_port: int):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((listen_host, listen_port))
    server.listen(256)

    log.info(f"Proxy listening on {listen_host}:{listen_port}")
    log.info(f"Using DNS server {dns_server}:{dns_port}")
    log.info(f"HTTP/HTTPS proxy address: {listen_host}:{listen_port}")

    try:
        while True:
            client, addr = server.accept()
            threading.Thread(
                target=handle_client,
                args=(client, addr, dns_server, dns_port),
                daemon=True,
            ).start()
    except KeyboardInterrupt:
        log.info("Shutting down.")
    finally:
        server.close()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Blind HTTP/HTTPS proxy with custom DNS (stdlib only)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--host", default="127.0.0.1", help="Address to listen on")
    parser.add_argument("--port", type=int, default=8080, help="Port to listen on")
    parser.add_argument("--dns", default="8.8.8.8", help="DNS server IP to use for lookups")
    parser.add_argument("--dns-port", type=int, default=53, help="DNS server port")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    run_proxy(args.host, args.port, args.dns, args.dns_port)


if __name__ == "__main__":
    main()
