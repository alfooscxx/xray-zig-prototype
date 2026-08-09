#!/usr/bin/env python3
import concurrent.futures
import json
import os
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path


ANSWER_IP = b"\xcb\x00\x71\x07"  # 203.0.113.7
QUERY_COUNT = int(os.environ.get("XRAY_ZIG_DNS_QUERY_COUNT", "32"))


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
    header = query[0:2] + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
    answer = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + ANSWER_IP
    return header + query[12:end] + answer


class DirectDnsServer:
    def __init__(self):
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(("127.0.0.1", 0))
        self.port = self.udp.getsockname()[1]
        self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.tcp.bind(("127.0.0.1", self.port))
        self.tcp.listen()
        self.stop = threading.Event()
        self.udp_queries = 0
        self.tcp_queries = 0

    def start(self):
        threading.Thread(target=self.answer_udp, daemon=True).start()
        threading.Thread(target=self.accept_tcp, daemon=True).start()

    def close(self):
        self.stop.set()
        self.udp.close()
        self.tcp.close()

    def answer_udp(self):
        while not self.stop.is_set():
            try:
                query, peer = self.udp.recvfrom(4096)
                self.udp_queries += 1
                self.udp.sendto(response_for(query), peer)
            except OSError:
                return

    def accept_tcp(self):
        while not self.stop.is_set():
            try:
                conn, _ = self.tcp.accept()
            except OSError:
                return
            threading.Thread(target=self.answer_tcp, args=(conn,), daemon=True).start()

    def answer_tcp(self, conn):
        with conn:
            try:
                length = recv_exactly(conn, 2)
                query = recv_exactly(conn, struct.unpack("!H", length)[0])
                response = response_for(query)
                conn.sendall(struct.pack("!H", len(response)) + response)
                self.tcp_queries += 1
            except (EOFError, OSError):
                return


def recv_exactly(sock, length):
    result = bytearray()
    while len(result) < length:
        data = sock.recv(length - len(result))
        if not data:
            raise EOFError("stream closed")
        result.extend(data)
    return bytes(result)


def query_packet(query_id):
    name = b"\x08fallback\x04test\x00"
    return struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0) + name + b"\x00\x01\x00\x01"


def run_query(port, query_id):
    packet = query_packet(query_id)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(3)
        sock.sendto(packet, ("127.0.0.1", port))
        response, _ = sock.recvfrom(4096)
    if response[0:2] != packet[0:2] or response[3] & 0x0F:
        raise RuntimeError("invalid DNS response")
    if not response.endswith(ANSWER_IP):
        raise RuntimeError("unexpected DNS answer")


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: dns-fallback.py /path/to/xray-zig")
    xray_zig = Path(sys.argv[1])
    if not xray_zig.is_file():
        raise SystemExit(f"xray-zig not found: {xray_zig}")

    upstream = DirectDnsServer()
    upstream.start()
    inbound_port = pick_port(socket.SOCK_DGRAM)

    config = {
        "dns": {
            "servers": [
                {
                    "resolver": f"127.0.0.1:{upstream.port}",
                    "outboundTag": "direct",
                    "domains": ["domain:"],
                }
            ]
        },
        "inbounds": [
            {
                "tag": "dns-in",
                "listen": "127.0.0.1",
                "port": inbound_port,
                "protocol": "dns",
            }
        ],
        "outbounds": [{"tag": "direct", "protocol": "freedom"}],
        "routing": {"defaultOutboundTag": "direct"},
    }

    with tempfile.TemporaryDirectory() as directory:
        config_path = Path(directory) / "config.json"
        config_path.write_text(json.dumps(config), encoding="ascii")
        process = subprocess.Popen(
            [str(xray_zig), "run", "-config", str(config_path)],
        )
        try:
            time.sleep(0.2)
            started = time.monotonic()
            with concurrent.futures.ThreadPoolExecutor(max_workers=QUERY_COUNT) as pool:
                futures = [pool.submit(run_query, inbound_port, index + 1) for index in range(QUERY_COUNT)]
                for future in futures:
                    future.result()
            elapsed = time.monotonic() - started
            if elapsed > 3:
                raise RuntimeError(f"DNS fallback was serialized or stalled: {elapsed:.3f}s")
            if upstream.udp_queries < QUERY_COUNT or upstream.tcp_queries != 0:
                raise RuntimeError(
                    f"unexpected transport counts: udp={upstream.udp_queries} tcp={upstream.tcp_queries}"
                )
            print(
                f"dns outbound ok: queries={QUERY_COUNT} elapsed_s={elapsed:.3f} "
                f"udp={upstream.udp_queries} tcp={upstream.tcp_queries}"
            )
        finally:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            upstream.close()


if __name__ == "__main__":
    main()
