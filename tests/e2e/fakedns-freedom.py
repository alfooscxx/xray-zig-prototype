#!/usr/bin/env python3
import json
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path


DOMAIN = b"freedom.invalid"
CLIENT_HELLO = b"\x16\x03\x01fake-client-hello"
SERVER_HELLO = b"\x16\x03\x03fake-server-hello"


def recv_exactly(sock, length):
    result = bytearray()
    while len(result) < length:
        data = sock.recv(length - len(result))
        if not data:
            raise EOFError("stream closed")
        result.extend(data)
    return bytes(result)


def pick_port(sock_type):
    with socket.socket(socket.AF_INET, sock_type) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def question_end(packet):
    offset = 12
    while True:
        length = packet[offset]
        offset += 1
        if length == 0:
            return offset + 4
        offset += length


def response_for(query):
    end = question_end(query)
    query_type = struct.unpack("!H", query[end - 4 : end - 2])[0]
    answer_count = 1 if query_type == 1 else 0
    header = query[0:2] + struct.pack("!HHHHH", 0x8180, 1, answer_count, 0, 0)
    if answer_count == 0:
        return header + query[12:end]
    answer = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x7f\x00\x00\x01"
    return header + query[12:end] + answer


class DnsServer:
    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(("127.0.0.1", 0))
        self.port = self.socket.getsockname()[1]
        self.stop = threading.Event()
        self.queries = 0

    def start(self):
        threading.Thread(target=self.answer, daemon=True).start()

    def close(self):
        self.stop.set()
        self.socket.close()

    def answer(self):
        while not self.stop.is_set():
            try:
                query, peer = self.socket.recvfrom(4096)
            except OSError:
                return
            try:
                self.socket.sendto(response_for(query), peer)
                self.queries += 1
            except OSError:
                return


class OriginServer:
    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(("127.0.0.1", 0))
        self.port = self.socket.getsockname()[1]
        self.socket.listen()
        self.received = None

    def start(self):
        threading.Thread(target=self.serve, daemon=True).start()

    def close(self):
        self.socket.close()

    def serve(self):
        try:
            connection, _ = self.socket.accept()
        except OSError:
            return
        with connection:
            try:
                self.received = recv_exactly(connection, len(CLIENT_HELLO))
                connection.sendall(SERVER_HELLO)
            except (EOFError, OSError):
                return


def socks_connect(port, target_port):
    with socket.create_connection(("127.0.0.1", port), timeout=3) as client:
        client.settimeout(3)
        client.sendall(b"\x05\x01\x00")
        if recv_exactly(client, 2) != b"\x05\x00":
            raise RuntimeError("SOCKS authentication failed")

        request = b"\x05\x01\x00\x03" + bytes([len(DOMAIN)]) + DOMAIN + struct.pack("!H", target_port)
        client.sendall(request)
        reply = recv_exactly(client, 10)
        if reply[0:2] != b"\x05\x00":
            raise RuntimeError(f"SOCKS connect failed: {reply.hex()}")

        client.sendall(CLIENT_HELLO)
        if recv_exactly(client, len(SERVER_HELLO)) != SERVER_HELLO:
            raise RuntimeError("freedom response did not reach the client")


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: fakedns-freedom.py /path/to/xray-zig")
    xray_zig = Path(sys.argv[1])
    if not xray_zig.is_file():
        raise SystemExit(f"xray-zig not found: {xray_zig}")

    dns = DnsServer()
    origin = OriginServer()
    dns.start()
    origin.start()
    socks_port = pick_port(socket.SOCK_STREAM)

    config = {
        "dns": {
            "servers": [
                {
                    "resolver": f"127.0.0.1:{dns.port}",
                    "outboundTag": "direct",
                    "domains": ["domain:"],
                }
            ],
            "fakeDns": {},
        },
        "inbounds": [
            {
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "port": socks_port,
                "protocol": "socks",
            }
        ],
        "outbounds": [{"tag": "direct", "protocol": "freedom"}],
        "routing": {"defaultOutboundTag": "direct"},
    }

    with tempfile.TemporaryDirectory() as directory:
        config_path = Path(directory) / "config.json"
        config_path.write_text(json.dumps(config), encoding="ascii")
        process = subprocess.Popen([str(xray_zig), "run", "-config", str(config_path)])
        try:
            time.sleep(0.2)
            socks_connect(socks_port, origin.port)
            if origin.received != CLIENT_HELLO:
                raise RuntimeError("client hello did not reach the freedom origin")
            if dns.queries != 2:
                raise RuntimeError(f"expected routed A and AAAA queries, got {dns.queries}")
            print("FakeDNS freedom resolution ok: routed_queries=2")
        finally:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            dns.close()
            origin.close()


if __name__ == "__main__":
    main()
