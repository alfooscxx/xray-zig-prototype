# Field Router Access

## Active target

The active field and deployment router is the AArch64 GL.iNet GL-MT6000.
Management, deployment, diagnostics, and tests use OpenSSH only. Supply the
destination explicitly rather than deriving it from the local default route:

```sh
export ROUTER_SSH=user@router-host
ssh -o BatchMode=yes "$ROUTER_SSH" 'uname -m; cat /etc/openwrt_release; hostname'
```

Proceed only when the identity is the expected router and `uname -m` reports
`aarch64`. Keep normal SSH host-key verification enabled. Do not put router
addresses, credentials, or private-key material in this repository.

Use `ssh` for commands and `scp` for transfers. HTTP administration endpoints,
command injection, RCE helpers, FTP, and scripts from the retired router
workflow are forbidden for this target.

## Legacy optical bridge

The old MIPS router now operates only as the bridge for the optical uplink. It
is not an xray-zig deployment or test target. Do not upload binaries or configs,
execute diagnostics or tests, install packages, or change its routes, firewall,
services, or boot state. Do not probe its management interface merely because
it appears as a gateway. Access requires a separate explicit request from the
user concerning the bridge itself.

Older MIPS build commands and measurements in dated documents are historical
records. They do not authorize deploying to the bridge.

## Safe field-test workflow

1. Confirm `ROUTER_SSH`, architecture, hostname, OS, free space, and existing
   xray-zig processes using read-only SSH commands.
2. Build `aarch64-linux-musl` with `-Dcpu=cortex_a53` and verify the ELF locally.
3. Copy artifacts to a unique directory under `/tmp`; do not overwrite the
   installed binary or production configuration.
4. Record existing interfaces, addresses, routes, and processes before the
   test. Use only temporary test state and avoid firewall or boot changes unless
   the user explicitly requests them.
5. Stop only processes started by the test and remove every temporary route,
   address, interface, process, and file when it completes or fails.

For TUN probes, also protect the proxy server route so the outbound REALITY
connection cannot be captured by the TUN route. UDP must remain disabled when
the requested field test is TCP-only.
