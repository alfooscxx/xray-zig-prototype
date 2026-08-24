# Local SK_LOOKUP Conformance Test

This privileged, local-only test isolates Linux `BPF_PROG_TYPE_SK_LOOKUP`
socket-selection behavior from xray-zig. It does not use an xray-zig config,
contact a router, change the host firewall, or deploy any artifact. Each case
runs in a fresh temporary network namespace; the harness trap removes the
namespace, attached programs, maps, processes, and temporary logs.

The server binds a wildcard TCP listener to port 19090 while the client connects
to the namespace-local address `198.51.100.1:19091`. Consequently, a successful
connect/accept/echo requires `bpf_sk_assign`; it cannot be satisfied by the
ordinary listener lookup.

The matrix contains:

- `direct`: one directly attached selector, used as the baseline.
- `chain`: an attached selector followed by an attached `SK_PASS` observer;
  the observer counts non-null `ctx->sk` values.
- `tail_call`: one attached dispatcher selects through a same-type program in
  a `PROG_ARRAY`.
- `cfg_load`: one selector with a configurable verifier-reachable branch that
  is not executed by the IPv4 probe. This varies CFG/instruction load without
  changing the selection path.

Build without running the privileged field matrix:

```sh
zig build sk-lookup-conformance
zig build test
sh -n tests/field/sk-lookup-conformance.sh
```

Run locally as root on a Linux kernel supporting SK_LOOKUP, SOCKMAP,
`bpf_sk_assign`, tail calls, and multi-program netns attachment:

```sh
sudo FORMAT=json CFG_BLOCKS=128 \
  tests/field/sk-lookup-conformance.sh \
  "$PWD/zig-out/bin/sk-lookup-conformance"
```

Set `ROUTED=1` to place the client behind a veth and deliver the target only
through an ingress policy rule plus a `local` route. Set `TRANSPARENT=1` to
enable `IP_TRANSPARENT` on the wildcard listener. The routed matrix is expected
to complete only with `TRANSPARENT=1`; this isolates listener transparency
from `bpf_sk_assign`, multi-attach, tail-call, and CFG behavior.

Set `FORMAT=tsv` for a header and tab-separated records. Every record reports
`case`, connect and accept/echo results, successful and failed
`bpf_sk_assign` return counters, the second program's `ctx_sk_seen` counter,
and the total instruction count across programs participating in the case.
The expected `ctx_sk_seen` value is one only for `chain`; successful assignment
is one in every case and the error counter is zero.

This is intentionally not part of `zig build test`: that command only compiles
the executable, runs its instruction-layout unit test, checks harness structure,
and parses the shell. The privileged matrix is always explicit.
