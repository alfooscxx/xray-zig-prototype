#!/bin/sh
set -eu

SOURCE=${1:-tests/field/sk-lookup-conformance.zig}
HARNESS=${2:-tests/field/sk-lookup-conformance.sh}

sh -n "$HARNESS"
grep -q 'MapType.*sockmap\|\.sockmap' "$SOURCE"
grep -q 'ProgType.sk_lookup' "$SOURCE"
grep -q 'AttachType.sk_lookup' "$SOURCE"
grep -q '\.link_create' "$SOURCE"
grep -q 'call(.sk_assign)' "$SOURCE"
grep -q 'call(.tail_call)' "$SOURCE"
grep -q 'ldx(.double_word, .r0, .r1, 0)' "$SOURCE"
grep -q 'ip netns add' "$HARNESS"
grep -q 'trap cleanup EXIT INT TERM HUP' "$HARNESS"
grep -q 'ip netns del' "$HARNESS"
