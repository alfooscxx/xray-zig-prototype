#!/usr/bin/env bash
set -euo pipefail

xray_zig="${1:?usage: reality-xray.sh /path/to/xray-zig}"

if [[ -z "${XRAY_BIN:-}" ]]; then
  echo "skip: set XRAY_BIN=/path/to/xray to run the Reality e2e harness"
  exit 0
fi

if [[ ! -x "${XRAY_BIN}" ]]; then
  echo "XRAY_BIN is not executable: ${XRAY_BIN}" >&2
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "skip: python3 is required for dynamic port allocation"
  exit 0
fi

tmp_dir="$(mktemp -d)"
xray_pid=""
zig_pid=""
echo_pid=""

cleanup() {
  if [[ -n "${zig_pid}" ]]; then kill "${zig_pid}" 2>/dev/null || true; fi
  if [[ -n "${xray_pid}" ]]; then kill "${xray_pid}" 2>/dev/null || true; fi
  if [[ -n "${echo_pid}" ]]; then kill "${echo_pid}" 2>/dev/null || true; fi
  rm -rf "${tmp_dir}"
}
trap cleanup EXIT

pick_port() {
  python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
}

wait_port() {
  local port="$1"
  local name="$2"
  for _ in $(seq 1 100); do
    if python3 - "${port}" <<'PY' >/dev/null 2>&1; then
import socket
import sys

sock = socket.socket()
sock.settimeout(0.05)
sock.connect(("127.0.0.1", int(sys.argv[1])))
sock.close()
PY
      return 0
    fi
    sleep 0.05
  done
  echo "timeout waiting for ${name} on 127.0.0.1:${port}" >&2
  return 1
}

server_port="$(pick_port)"
client_port="$(pick_port)"
vision_client_port="$(pick_port)"

normal_user_id="00000000-0000-0000-0000-000000000000"
vision_user_id="11111111-1111-1111-1111-111111111111"
private_key="aGSYystUbf59_9_6LKRxD27rmSW_-2_nyd9YG_Gwbks"
public_key="E59WjnvZcQMu7tR7_BgyhycuEdBS-CtKxfImRCdAvFM"
short_id="0123456789abcdef"
server_name="www.google.com"

xray_config="${tmp_dir}/xray-server.json"
zig_config="${tmp_dir}/xray-zig-client.json"
zig_vision_config="${tmp_dir}/xray-zig-vision-client.json"

cat >"${xray_config}" <<JSON
{
  "log": {
    "access": "${tmp_dir}/xray-access.log",
    "loglevel": "debug"
  },
  "inbounds": [
    {
      "tag": "vless-reality-in",
      "listen": "127.0.0.1",
      "port": ${server_port},
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "${normal_user_id}",
            "flow": ""
          },
          {
            "id": "${vision_user_id}",
            "flow": "xtls-rprx-vision"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": true,
          "dest": "${server_name}:443",
          "serverNames": ["${server_name}"],
          "privateKey": "${private_key}",
          "shortIds": ["${short_id}"]
        }
      }
    }
  ],
  "outbounds": [
    {
      "tag": "direct",
      "protocol": "freedom"
    }
  ]
}
JSON

cat >"${zig_config}" <<JSON
{
  "inbounds": [
    {
      "tag": "socks-in",
      "listen": "127.0.0.1",
      "port": ${client_port},
      "protocol": "socks"
    }
  ],
  "outbounds": [
    {
      "tag": "proxy",
      "protocol": "vless",
      "settings": {
        "vnext": [
          {
            "address": "127.0.0.1",
            "port": ${server_port},
            "users": [
              {
                "id": "${normal_user_id}"
              }
            ]
          }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "serverName": "${server_name}",
          "publicKey": "${public_key}",
          "shortId": "${short_id}"
        }
      }
    }
  ],
  "routing": {
    "defaultOutboundTag": "proxy"
  }
}
JSON

cat >"${zig_vision_config}" <<JSON
{
  "inbounds": [
    {
      "tag": "socks-in",
      "listen": "127.0.0.1",
      "port": ${vision_client_port},
      "protocol": "socks"
    }
  ],
  "outbounds": [
    {
      "tag": "proxy",
      "protocol": "vless",
      "settings": {
        "vnext": [
          {
            "address": "127.0.0.1",
            "port": ${server_port},
            "users": [
              {
                "id": "${vision_user_id}",
                "flow": "xtls-rprx-vision"
              }
            ]
          }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "cipherPolicy": "chacha20-only",
          "serverName": "${server_name}",
          "publicKey": "${public_key}",
          "shortId": "${short_id}"
        }
      }
    }
  ],
  "routing": {
    "defaultOutboundTag": "proxy"
  }
}
JSON

"${XRAY_BIN}" run -test -config "${xray_config}" >/dev/null
"${xray_zig}" check -config "${zig_config}" >/dev/null
"${xray_zig}" check -config "${zig_vision_config}" >/dev/null

"${XRAY_BIN}" run -config "${xray_config}" >"${tmp_dir}/xray.log" 2>&1 &
xray_pid="$!"
wait_port "${server_port}" "xray reality server"

echo "e2e setup ok: real Xray Reality server listening on ${server_port}; Vision client forces ChaCha20"

if [[ "${XRAY_ZIG_REALITY_TRAFFIC:-0}" != "1" ]]; then
  echo "skip traffic: set XRAY_ZIG_REALITY_TRAFFIC=1 to run the SOCKS -> Zig Reality -> Xray traffic probe"
  exit 0
fi

run_traffic_probe() {
  local label="$1"
  local config="$2"
  local port="$3"
  local echo_port

  echo_port="$(pick_port)"
  python3 - "${echo_port}" <<'PY' &
import socket
import sys

sock = socket.socket()
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(("127.0.0.1", int(sys.argv[1])))
sock.listen(1)
conn, _ = sock.accept()
conn.sendall(b"ready")
request = b""
while len(request) < 4:
    chunk = conn.recv(4 - len(request))
    if not chunk:
        raise RuntimeError("client closed before sending post-preface payload")
    request += chunk
if request != b"ping":
    raise RuntimeError(f"unexpected request: {request!r}")
conn.sendall(b"pong")
conn.close()
sock.close()
PY
  echo_pid="$!"

  "${xray_zig}" run -config "${config}" >"${tmp_dir}/xray-zig-${label}.log" 2>&1 &
  zig_pid="$!"
  wait_port "${port}" "xray-zig ${label} socks inbound"

  result="$(python3 - "${port}" "${echo_port}" <<'PY'
import socket
import struct
import sys


def read_exact(sock, length):
    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise RuntimeError("unexpected EOF")
        data += chunk
    return data


socks_port = int(sys.argv[1])
target_port = int(sys.argv[2])
sock = socket.create_connection(("127.0.0.1", socks_port), timeout=20)
sock.settimeout(20)
sock.sendall(b"\x05\x01\x00")
if read_exact(sock, 2) != b"\x05\x00":
    raise RuntimeError("SOCKS authentication negotiation failed")
sock.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + struct.pack(">H", target_port))
reply = read_exact(sock, 10)
if reply[:2] != b"\x05\x00":
    raise RuntimeError(f"SOCKS connect failed: {reply!r}")
if read_exact(sock, 5) != b"ready":
    raise RuntimeError("missing server readiness marker")
sock.sendall(b"ping")
print(read_exact(sock, 4).decode("ascii"), end="")
sock.close()
PY
)"
  if [[ "${result}" != "pong" ]]; then
    echo "unexpected ${label} e2e response: ${result}" >&2
    echo "--- xray server log ---" >&2
    cat "${tmp_dir}/xray.log" >&2 || true
    echo "--- xray-zig ${label} log ---" >&2
    cat "${tmp_dir}/xray-zig-${label}.log" >&2 || true
    echo "--- xray access log ---" >&2
    cat "${tmp_dir}/xray-access.log" >&2 || true
    exit 1
  fi

  wait "${echo_pid}" 2>/dev/null || true
  echo_pid=""
  kill "${zig_pid}" 2>/dev/null || true
  wait "${zig_pid}" 2>/dev/null || true
  zig_pid=""
  echo "Reality ${label} e2e traffic ok"
}

run_traffic_probe "normal" "${zig_config}" "${client_port}"
run_traffic_probe "vision" "${zig_vision_config}" "${vision_client_port}"
