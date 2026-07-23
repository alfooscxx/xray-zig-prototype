#!/usr/bin/env python3
import argparse
import base64
import concurrent.futures
import hashlib
import os
import socket
import ssl
import statistics
import struct
import time


WEBSOCKET_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


class FragmentedTls:
    def __init__(self, sock, server_name, fragment_size, fragment_delay):
        self.sock = sock
        self.fragment_size = fragment_size
        self.fragment_delay = fragment_delay
        self.incoming = ssl.MemoryBIO()
        self.outgoing = ssl.MemoryBIO()
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.tls = context.wrap_bio(
            self.incoming, self.outgoing, server_hostname=server_name
        )
        self.cleartext = bytearray()

    def flush(self):
        while True:
            encrypted = self.outgoing.read()
            if not encrypted:
                return
            for offset in range(0, len(encrypted), self.fragment_size):
                self.sock.sendall(encrypted[offset : offset + self.fragment_size])
                if self.fragment_delay:
                    time.sleep(self.fragment_delay)

    def handshake(self):
        while True:
            try:
                self.tls.do_handshake()
                self.flush()
                return
            except ssl.SSLWantReadError:
                self.flush()
                self._receive_encrypted()

    def write(self, data):
        view = memoryview(data)
        while view:
            try:
                written = self.tls.write(view)
                view = view[written:]
                self.flush()
            except ssl.SSLWantWriteError:
                self.flush()

    def read_exactly(self, length):
        while len(self.cleartext) < length:
            self._receive_cleartext()
        result = bytes(self.cleartext[:length])
        del self.cleartext[:length]
        return result

    def read_until(self, marker, limit=65536):
        while marker not in self.cleartext:
            if len(self.cleartext) >= limit:
                raise RuntimeError("TLS cleartext limit exceeded")
            self._receive_cleartext()
        end = self.cleartext.index(marker) + len(marker)
        result = bytes(self.cleartext[:end])
        del self.cleartext[:end]
        return result

    def _receive_cleartext(self):
        while True:
            try:
                data = self.tls.read(65536)
                if not data:
                    raise EOFError("TLS stream closed")
                self.cleartext.extend(data)
                return
            except ssl.SSLWantReadError:
                self.flush()
                self._receive_encrypted()

    def _receive_encrypted(self):
        data = self.sock.recv(65536)
        if not data:
            raise EOFError("TCP stream closed")
        self.incoming.write(data)


def connect_socks(proxy_host, proxy_port, target_host, target_port, timeout):
    sock = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    sock.settimeout(timeout)
    sock.sendall(b"\x05\x01\x00")
    if sock.recv(2) != b"\x05\x00":
        raise RuntimeError("SOCKS authentication negotiation failed")
    host = target_host.encode("idna")
    if len(host) > 255:
        raise ValueError("target host is too long")
    sock.sendall(b"\x05\x01\x00\x03" + bytes([len(host)]) + host + struct.pack("!H", target_port))
    reply = recv_exactly(sock, 4)
    if reply[1] != 0:
        raise RuntimeError(f"SOCKS connect failed with reply {reply[1]}")
    address_type = reply[3]
    if address_type == 1:
        recv_exactly(sock, 4)
    elif address_type == 3:
        recv_exactly(sock, recv_exactly(sock, 1)[0])
    elif address_type == 4:
        recv_exactly(sock, 16)
    else:
        raise RuntimeError("invalid SOCKS address type")
    recv_exactly(sock, 2)
    return sock


def recv_exactly(sock, length):
    result = bytearray()
    while len(result) < length:
        data = sock.recv(length - len(result))
        if not data:
            raise EOFError("SOCKS stream closed")
        result.extend(data)
    return bytes(result)


def client_frame(opcode, payload=b""):
    mask = os.urandom(4)
    length = len(payload)
    header = bytearray([0x80 | opcode])
    if length < 126:
        header.append(0x80 | length)
    elif length <= 0xFFFF:
        header.append(0x80 | 126)
        header.extend(struct.pack("!H", length))
    else:
        header.append(0x80 | 127)
        header.extend(struct.pack("!Q", length))
    header.extend(mask)
    masked = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
    return bytes(header) + masked


def read_server_frame(tls):
    first, second = tls.read_exactly(2)
    if second & 0x80:
        raise RuntimeError("server frame must not be masked")
    length = second & 0x7F
    if length == 126:
        length = struct.unpack("!H", tls.read_exactly(2))[0]
    elif length == 127:
        length = struct.unpack("!Q", tls.read_exactly(8))[0]
    return first & 0x0F, tls.read_exactly(length)


def run_client(index, args):
    started = time.monotonic()
    if args.direct:
        sock = socket.create_connection(
            (args.target_host, args.target_port), timeout=args.timeout
        )
        sock.settimeout(args.timeout)
    else:
        sock = connect_socks(
            args.proxy_host,
            args.proxy_port,
            args.target_host,
            args.target_port,
            args.timeout,
        )
    try:
        if args.post_connect_delay:
            time.sleep(args.post_connect_delay / 1000)
        tls = FragmentedTls(
            sock, args.server_name, args.fragment_size, args.fragment_delay / 1000
        )
        tls.handshake()
        key = base64.b64encode(os.urandom(16)).decode()
        request = (
            f"GET /echo HTTP/1.1\r\nHost: {args.server_name}\r\n"
            "Upgrade: websocket\r\nConnection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        ).encode()
        tls.write(request)
        response = tls.read_until(b"\r\n\r\n")
        expected_accept = base64.b64encode(
            hashlib.sha1((key + WEBSOCKET_GUID).encode()).digest()
        )
        if not response.startswith(b"HTTP/1.1 101") or expected_accept not in response:
            raise RuntimeError("WebSocket upgrade failed")

        for sequence in range(args.frames):
            payload = f"client={index} sequence={sequence}".encode()
            tls.write(client_frame(0x2, payload))
            opcode, echoed = read_server_frame(tls)
            if opcode != 0x2 or echoed != payload:
                raise RuntimeError("echo mismatch")
            if sequence % args.ping_interval == 0:
                ping = struct.pack("!II", index, sequence)
                tls.write(client_frame(0x9, ping))
                opcode, pong = read_server_frame(tls)
                if opcode != 0xA or pong != ping:
                    raise RuntimeError("ping/pong mismatch")
        tls.write(client_frame(0x8, b"\x03\xe8"))
        return time.monotonic() - started
    finally:
        sock.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--proxy-host", default="192.168.1.1")
    parser.add_argument("--proxy-port", type=int, default=21080)
    parser.add_argument("--direct", action="store_true")
    parser.add_argument("--target-host", required=True)
    parser.add_argument("--target-port", type=int, default=19101)
    parser.add_argument("--server-name", default="wss-field.test")
    parser.add_argument("--clients", type=int, default=16)
    parser.add_argument("--frames", type=int, default=100)
    parser.add_argument("--ping-interval", type=int, default=10)
    parser.add_argument("--fragment-size", type=int, default=7)
    parser.add_argument("--fragment-delay", type=float, default=1.0, help="milliseconds")
    parser.add_argument(
        "--post-connect-delay",
        type=float,
        default=0,
        help="milliseconds to wait after SOCKS CONNECT before starting TLS",
    )
    parser.add_argument(
        "--launch-delay",
        type=float,
        default=0,
        help="milliseconds to wait between starting concurrent clients",
    )
    parser.add_argument("--timeout", type=float, default=30)
    args = parser.parse_args()

    started = time.monotonic()
    durations = []
    failures = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.clients) as pool:
        futures = {}
        for index in range(args.clients):
            future = pool.submit(run_client, index, args)
            futures[future] = index
            if args.launch_delay:
                time.sleep(args.launch_delay / 1000)
        for future, index in [(future, futures[future]) for future in futures]:
            try:
                durations.append(future.result())
            except Exception as error:
                failures.append((index, repr(error)))

    elapsed = time.monotonic() - started
    completed_frames = len(durations) * args.frames
    print(
        f"clients={len(durations)}/{args.clients} frames={completed_frames}/{args.clients * args.frames} "
        f"elapsed_s={elapsed:.3f} mean_client_s={statistics.mean(durations) if durations else 0:.3f} "
        f"max_client_s={max(durations) if durations else 0:.3f} failures={len(failures)}"
    )
    for index, error in failures:
        print(f"failure client={index}: {error}")
    raise SystemExit(1 if failures else 0)


if __name__ == "__main__":
    main()
