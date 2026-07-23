# xtls-rprx-vision Implementation Notes

## Scope

Client-side `xtls-rprx-vision` for VLESS over Reality/TLS is implemented. Configs with `flow: "xtls-rprx-vision"` run against a real Xray server. UDP and `xtls-rprx-vision-udp443` remain out of scope.

## Source References

The Go implementation in the parent Xray-core repository was used as the behavioral reference:

- `proxy/vless/encoding/addons.go`: VLESS header addon protobuf with `Flow = 1`.
- `proxy/vless/encoding/encoding.go`: request/response header ordering.
- `proxy/proxy.go`: `TrafficState`, Vision padding, unpadding, TLS filtering, and direct-copy transition.
- `proxy/vless/outbound/outbound.go`: where Vision wraps uplink/downlink after Reality/TLS is established.

## Implementation Summary

1. Done: accept only `xtls-rprx-vision` in `validateVlessOutbound`; unknown non-empty flows and `xtls-rprx-vision-udp443` are rejected.
2. Done: encode VLESS header addons in `src/proxy/vless/outbound.zig` as protobuf field `1` string `Flow`, length-prefixed before the command byte. Normal VLESS keeps zero-length addons.
3. Done: `src/proxy/vless/vision.zig` contains `TrafficState`, padding, unpadding, TLS filtering, and direct-command state. `CommandDirect` switches both directions from the outer REALITY/TLS stream to raw TCP after draining buffered input. Kernel splice remains intentionally out of scope.
4. Done: `vless.handle` uses a Vision writer for client-to-server and a Vision reader for server-to-client when the outbound flow is Vision.
5. Done: unit coverage includes addon protobuf encoding, fixed padding/unpadding vectors, TLS ClientHello detection, TLS 1.3/direct-command state transitions, and TLS application-data completeness.
6. Done: the real Xray e2e harness has normal and Vision users and runs SOCKS traffic through both Zig clients when `XRAY_ZIG_REALITY_TRAFFIC=1`. Its server remains open while a second small client write crosses the tunnel, guarding against buffered reads that wait for 16 KiB or EOF.

## Acceptance

- Existing non-Vision VLESS Reality e2e still passes.
- A Vision Reality e2e against `/tmp/codex-xray-bin/xray` passes with `flow: "xtls-rprx-vision"`.
- Unknown VLESS flows fail validation with a clear unsupported-flow error.

Verified on 2026-07-22 from the `xray-zig/` project root with:

- `zig build test`
- `zig build run -- check -config tests/fixtures/minimal-redirect-reality.json`
- `zig build run -- check -config tests/fixtures/minimal-socks.json`
- `XRAY_BIN=/tmp/codex-xray-bin/xray XRAY_ZIG_REALITY_TRAFFIC=1 zig build e2e-reality`
- Real field-server probes using `field-config-test.json`'s `proxy` outbound wrapped in a temporary SOCKS inbound returned HTTPS 200 responses from Wikipedia, IANA, Cloudflare, example.com, jsDelivr, and Google AJAX. A 1 MiB Cloudflare transfer also completed through Vision direct copy.

Compatibility note: after the 2026-06-20 TLS policy correction, the Zig TLS ClientHello offers TLS 1.3 and TLS 1.2 but never sends an ECH or GREASE ECH extension. The real Xray Reality e2e traffic probe passes with TLS 1.3 negotiation.

MIPS performance note: Xray's server-side Vision writer does not always enter downlink direct copy. Its decision depends on receiving complete inner TLS records from the destination in one buffer group, so behavior is origin- and packet-boundary-dependent. When traffic remains inside outer REALITY/TLS, `AES_128_GCM_SHA256` is prohibitively expensive on the field MIPS32 CPU. The explicit `realitySettings.cipherPolicy: "chacha20-only"` mode removes AES suites while retaining TLS 1.3 and TLS 1.2 ChaCha20 suites. It changes the cipher-suite fingerprint and should be enabled only when that CPU/server tradeoff is acceptable.

Important interop fix: REALITY reads must return already-decrypted buffered TLS plaintext before waiting for another network record. The field Xray server can send the VLESS response header and Vision response bytes in the same TLS application record while keeping the connection open.

Vision framing must preserve inner TLS record boundaries until `CommandDirect`. The initial payload reader reads exactly the five-byte TLS header and its declared payload, without consuming bytes from a following record. The uplink pump likewise assembles complete TLS records before passing them to the Vision writer. This is required because Xray only emits `CommandDirect` when its TLS filter receives complete application-data records; arbitrary TCP read fragments can leave the connection on the expensive outer-TLS path.

Record assembly must remain non-blocking with respect to the opposite direction. `forwardUplinkOnce` reads at most one available fragment, stores its pending length, and returns to the socket poll loop when the record is incomplete. The earlier loop that synchronously waited for the remaining record bytes blocked downstream handling and caused broad interactive-traffic failures, including WebSocket interruption.

The client-side TCP pump uses short `readVec` operations while assembling those records. Zig 0.16's `readSliceShort` fills the requested slice until EOF, so using it with a 16 KiB buffer stalls post-handshake TLS records on persistent HTTPS connections.

REALITY direct-read and direct-write flags must be initialized explicitly in `Client.init`. `OutboundConnection` initializes the union payload as `undefined`, so relying on struct field defaults caused optimized builds to switch to raw TCP before Vision `CommandDirect`; ReleaseSafe trapped on the invalid boolean and ReleaseFast failed most TLS sessions.
