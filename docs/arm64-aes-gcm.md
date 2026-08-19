# Arm64 OpenWRT AES-GCM

## Target

The field target was a GL.iNet GL-MT6000 running OpenWRT 25.12.5 on four
Cortex-A53 cores. `/proc/cpuinfo` reports the `aes` and `pmull` features on
every core.

Zig 0.16 selects its AArch64 AES and GHASH implementations at compile time.
The `cortex_a53` CPU model enables both features, so the resulting TLS code
uses `AESE`/`AESMC` for AES and `PMULL` for GHASH. A generic AArch64 baseline
build uses the software implementations even when run on this router.

Build the router binary with:

```sh
zig build \
  -Dtarget=aarch64-linux-musl \
  -Dcpu=cortex_a53 \
  -Doptimize=ReleaseFast \
  --prefix zig-out-arm64-release
```

The CPU specialization is required. Verify the unstripped artifact before
deployment:

```sh
llvm-objdump -d zig-out-arm64-release/bin/xray-zig | rg '\b(aese|aesmc|pmull|pmull2)\b'
```

## Measured Crypto Paths

`tools/crypto-bench.zig` uses the same Zig `Aes128Gcm` and
`ChaCha20Poly1305` implementations as the TLS record layer. It processes
16 KiB records and counts encryption plus decryption throughput. ReleaseFast
results on the GL-MT6000 were:

| Build | AES-128-GCM | ChaCha20-Poly1305 |
| --- | ---: | ---: |
| `aarch64-linux-musl -mcpu cortex_a53` | 416.18 MiB/s | 114.81 MiB/s |
| `aarch64-linux-musl -mcpu baseline` | 17.04 MiB/s | 94.50 MiB/s |

Hardware AES/PMULL was 24.4 times faster than the generic software AES path
and 3.6 times faster than hardware-build ChaCha20 on this device.

Rebuild the benchmark with:

```sh
zig build-exe tools/crypto-bench.zig \
  -O ReleaseFast -target aarch64-linux-musl -mcpu cortex_a53 \
  -femit-bin=/tmp/xray-zig-crypto-bench-a53
zig build-exe tools/crypto-bench.zig \
  -O ReleaseFast -target aarch64-linux-musl -mcpu baseline \
  -femit-bin=/tmp/xray-zig-crypto-bench-baseline
```

The kernel also registers `safexcel-gcm-aes` and `gcm-aes-ce`. They are not
currently accessible to userspace: an AF_ALG socket returns
`EAFNOSUPPORT`, and the installed firmware has no `af_alg` or `algif_aead`
module. `tools/afalg-aes-gcm-bench.c` records the probe used for this check.
Using Safexcel from the TLS client would therefore require a firmware or
kernel-package change before its syscall and asynchronous-request overhead
could be measured. The existing CPU-instruction path requires no router
package or kernel changes and is the supported path.

## Firefox And Negotiated Cipher

The generic `firefox` fingerprint tracks the Firefox 148 ClientHello profile,
while keeping the project's REALITY-compatible no-ECH rule. Its TLS 1.3
cipher order begins with:

```text
TLS_AES_128_GCM_SHA256
TLS_CHACHA20_POLY1305_SHA256
TLS_AES_256_GCM_SHA384
```

This is a Firefox 148-compatible no-ECH profile, not a claim of byte-for-byte
identity with Firefox when the browser sends GREASE ECH. The explicit
`hellofirefox_105` and `hellofirefox_120` profiles remain available.

For hardware AES targets, keep both values at their defaults or specify them
explicitly:

```json
{
  "fingerprint": "firefox",
  "cipherPolicy": "firefox"
}
```

`chacha20-only` remains an opt-in policy for software-AES systems and changes
the cipher-suite fingerprint.

A trace build logs the outer REALITY TLS result after each handshake. The
field test used a loopback-only SOCKS inbound on the router, reached through
SSH local forwarding; it made no firewall changes. Both HTTPS and plaintext
HTTP requests succeeded. The outer handshake reported:

```text
reality tls=tls_1_3 cipher=AES_128_GCM_SHA256 aes_hardware=true fingerprint=firefox policy=firefox
```

The plaintext HTTP request did not enter Vision direct copy, so its payload
continued through the outer hardware-accelerated AES-GCM record layer.
