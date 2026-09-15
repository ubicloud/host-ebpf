#!/bin/bash
# Integration rig for the ndp-proxy program and its loader. Requires root
# and a 6.6+ kernel. Drives the real host-ebpf binary, so the map layouts
# it writes are the ones under test.
#
# Topology: netns "ndp-router" simulates a provider router that treats the
# host's /64 as on-link; netns "ndp-host" is the hypervisor host, with a
# stub vetho device carrying the route for a delegated VM /79.
#
#   ndp-router [rt0] 2001:db8:aa::1/64 <--veth--> [up0] 2001:db8:aa::2/64 [ndp-host]
#                                                  vetho0 <- 2001:db8:aa:0:1388::/79
#                                                  vetho0 <- 2001:db8:aa:0:2000::/79 via fe80::1 (the production shape)
#                                                  vetho0 <- 2001:db8:bb::/64 (outside the configured prefix)
set -ueo pipefail

cd "$(dirname "$0")/.."
BIN=$PWD/host-ebpf
NET6_HOST=2001:db8:aa::2
NET6_ROUTER=2001:db8:aa::1
PREFIX=2001:db8:aa::/64
VM_TARGET=2001:db8:aa:0:1388::2
GW_TARGET=2001:db8:aa:0:2000::2
UNALLOCATED=2001:db8:aa::dead
FOREIGN_ROUTED=2001:db8:bb::1

[ "$(id -u)" = 0 ] || { echo "must run as root"; exit 1; }
[ -x "$BIN" ] || { echo "missing $BIN; run make first"; exit 1; }

FAILURES=0
fail() { echo "FAIL: $1"; FAILURES=$((FAILURES + 1)); }
pass() { echo "PASS: $1"; }

NSTOOL=$(mktemp)
CKTOOL=$(mktemp)

cleanup() {
  ip netns del ndp-router 2>/dev/null || true
  ip netns del ndp-host 2>/dev/null || true
  rm -f "$NSTOOL" "$CKTOOL"
}
trap cleanup EXIT
cleanup 2>/dev/null || true

ip netns add ndp-router
ip netns add ndp-host
ip link add rt0 netns ndp-router type veth peer name up0 netns ndp-host

nsenter --net=/run/netns/ndp-host sysctl -qw net.ipv6.conf.all.forwarding=1
ip -n ndp-router link set rt0 up
ip -n ndp-host link set up0 up
ip -n ndp-router addr add "$NET6_ROUTER/64" dev rt0 nodad
ip -n ndp-host addr add "$NET6_HOST/64" dev up0 nodad

ip -n ndp-host link add vetho0 type dummy
ip -n ndp-host link set vetho0 up
ip -n ndp-host route add 2001:db8:aa:0:1388::/79 dev vetho0
# VmSetup routes a VM's prefix via the vethi link-local address; nothing ever
# resolves that neighbor from the host side.
ip -n ndp-host route add 2001:db8:aa:0:2000::/79 via fe80::1 dev vetho0
ip -n ndp-host route add 2001:db8:bb::/64 dev vetho0

# The loader pins under /sys/fs/bpf, which "ip netns exec" hides by
# remounting /sys, so enter only the network namespace.
in_host() { nsenter --net=/run/netns/ndp-host "$@"; }

in_host "$BIN" ndp-proxy apply -uplink up0 -prefix "$PREFIX"
UP_MAC=$(ip -n ndp-host -j link show up0 | python3 -c \
  'import json, sys; print(json.load(sys.stdin)[0]["address"])')

# Wait for link-local DAD on the veths.
sleep 2

counter() {
  in_host "$BIN" ndp-proxy counters -json |
    python3 -c 'import json, sys; print(json.load(sys.stdin)[sys.argv[1]])' "$1"
}

cat > "$NSTOOL" <<'PY'
import socket, struct, sys

target_str, dst, hops, expect_na = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4] == "1"
target = socket.inet_pton(socket.AF_INET6, target_str)
s = socket.socket(socket.AF_INET6, socket.SOCK_RAW, 58)
s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, hops)
s.settimeout(2)
s.sendto(struct.pack("!BBHI", 135, 0, 0, 0) + target, (dst, 0))
try:
    while True:
        data, addr = s.recvfrom(2048)
        if len(data) >= 24 and data[0] == 136 and data[8:24] == target:
            assert expect_na, "unexpected NA"
            assert data[4] == 0xc0, "flags %#x != R|S with Override clear" % data[4]
            assert len(data) == 24, "expected no TLL option, len %d" % len(data)
            assert addr[0].split("%")[0] == socket.inet_ntop(socket.AF_INET6, target), \
                "NA source %s is not the target" % addr[0]
            sys.exit(0)
except socket.timeout:
    sys.exit(1 if expect_na else 0)
PY

# Raw ICMPv6 sockets always compute a correct checksum, so craft the whole
# frame on an AF_PACKET socket to corrupt it.
cat > "$CKTOOL" <<'PY'
import socket, struct, sys

target = socket.inet_pton(socket.AF_INET6, sys.argv[1])
src = socket.inet_pton(socket.AF_INET6, "2001:db8:aa::1")
dst = socket.inet_pton(socket.AF_INET6, "2001:db8:aa::2")
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind(("rt0", 0))
smac = s.getsockname()[4]
dmac = bytes.fromhex(sys.argv[2].replace(":", ""))
# Deliberately wrong checksum, everything else valid.
icmp = struct.pack("!BBHI", 135, 0, 0xdead, 0) + target
pkt = dmac + smac + b"\x86\xdd" + struct.pack("!IHBB", 0x60000000, len(icmp), 58, 255) + src + dst + icmp
s.send(pkt)

r = socket.socket(socket.AF_INET6, socket.SOCK_RAW, 58)
r.settimeout(2)
try:
    while True:
        data, _ = r.recvfrom(2048)
        if len(data) >= 24 and data[0] == 136 and data[8:24] == target:
            sys.exit(1)
except socket.timeout:
    sys.exit(0)
PY

# 1. Multicast NS (carrying a source link-layer option) for an address routed
#    via vetho: answered with the uplink MAC.
OUT=$(ip netns exec ndp-router ndisc6 -w 2000 -r 2 "$VM_TARGET" rt0 2>&1) &&
  echo "$OUT" | grep -qi "$UP_MAC" &&
  pass "delegated target answered with uplink MAC" ||
  fail "delegated target not answered: $OUT"

# 1b. The production route shape: a gateway route through a link-local
#     nexthop with no neighbor entry, which SKIP_NEIGH makes resolvable.
OUT=$(ip netns exec ndp-router ndisc6 -w 2000 -r 2 "$GW_TARGET" rt0 2>&1) &&
  echo "$OUT" | grep -qi "$UP_MAC" &&
  pass "gateway-routed target answered with uplink MAC" ||
  fail "gateway-routed target not answered: $OUT"

# 2. Unallocated address in the /64: best route is the uplink itself, no NA.
ip netns exec ndp-router ndisc6 -w 1000 -r 1 "$UNALLOCATED" rt0 >/dev/null 2>&1 &&
  fail "unallocated address was answered" ||
  pass "unallocated address stays silent"
[ "$(counter pass_fib_uplink)" -ge 1 ] &&
  pass "fib-uplink counter moved" || fail "fib-uplink counter still zero"

# 3. Routed off-uplink but outside the configured prefix: the guard refuses.
ip netns exec ndp-router ndisc6 -w 1000 -r 1 "$FOREIGN_ROUTED" rt0 >/dev/null 2>&1 &&
  fail "foreign routed prefix was answered" ||
  pass "prefix guard stays silent"
[ "$(counter pass_prefix_miss)" -ge 1 ] &&
  pass "prefix-miss counter moved" || fail "prefix-miss counter still zero"

# 4. Host-local target passes through to the kernel, which answers.
OUT=$(ip netns exec ndp-router ndisc6 -w 2000 -r 2 "$NET6_HOST" rt0 2>&1) &&
  echo "$OUT" | grep -qi "$UP_MAC" &&
  pass "host-local target answered by the kernel" ||
  fail "host-local target not answered: $OUT"
[ "$(counter pass_fib_local)" -ge 1 ] &&
  pass "fib-local counter moved" || fail "fib-local counter still zero"

# 5. Unicast NS without a link-layer option: answered without a TLL option,
#    sourced from the target, Router|Solicited with Override clear.
ip netns exec ndp-router python3 "$NSTOOL" "$VM_TARGET" "$NET6_HOST" 255 1 &&
  pass "optionless unicast NS answered correctly" ||
  fail "optionless unicast NS case failed"

# 6. Hop limit != 255 is ignored (RFC 4861 7.1.1).
BEFORE=$(counter pass_malformed)
ip netns exec ndp-router python3 "$NSTOOL" "$VM_TARGET" "$NET6_HOST" 200 0 &&
  pass "low hop limit NS not answered" ||
  fail "low hop limit NS was answered"
[ "$(counter pass_malformed)" -gt "$BEFORE" ] &&
  pass "malformed counter moved" || fail "malformed counter did not move"

# 7. A corrupt ICMPv6 checksum is ignored, as the kernel responder would.
BEFORE=$(counter pass_malformed)
ip netns exec ndp-router python3 "$CKTOOL" "$VM_TARGET" "$UP_MAC" &&
  pass "bad checksum NS not answered" ||
  fail "bad checksum NS was answered"
[ "$(counter pass_malformed)" -gt "$BEFORE" ] &&
  pass "malformed counter moved for bad checksum" ||
  fail "malformed counter did not move for bad checksum"

# 8. Duplicate address detection for an address inside the delegated range is
#    not defended, so the router's kernel keeps the address.
ip -n ndp-router addr add 2001:db8:aa:0:1388::99/64 dev rt0
sleep 2
ip -n ndp-router -j addr show dev rt0 | grep -q dadfailed &&
  fail "DAD was answered (dadfailed on router)" ||
  pass "DAD not defended"
[ "$(counter pass_dad)" -ge 1 ] &&
  pass "dad counter moved" || fail "dad counter still zero"

[ "$(counter answered)" -ge 3 ] &&
  pass "answered counter consistent" || fail "answered counter below expectation"

# 8b. Re-applying swaps the program in on the pinned link: the attachment
#     stays healthy, counters restart with the new maps, and answers continue.
in_host "$BIN" ndp-proxy apply -uplink up0 -prefix "$PREFIX"
in_host "$BIN" ndp-proxy verify -uplink up0 -prefix "$PREFIX" >/dev/null &&
  pass "re-apply keeps the attachment healthy" || fail "re-apply left drift"
[ "$(counter answered)" -eq 0 ] &&
  pass "re-apply restarted the counters" || fail "counters survived re-apply"
OUT=$(ip netns exec ndp-router ndisc6 -w 2000 -r 2 "$VM_TARGET" rt0 2>&1) &&
  echo "$OUT" | grep -qi "$UP_MAC" &&
  pass "delegated target answered after re-apply" ||
  fail "delegated target not answered after re-apply: $OUT"

# 9. A healthy attachment reports no drift.
in_host "$BIN" ndp-proxy verify -uplink up0 -prefix "$PREFIX" >/dev/null &&
  pass "verify reports healthy" || fail "verify reported drift on a healthy attachment"

# 10. Drift is detected and healed, and the pre-heal counters are surfaced.
in_host "$BIN" ndp-proxy verify -uplink up0 -prefix 2001:db8:cc::/64 >/dev/null 2>&1 &&
  fail "verify accepted the wrong prefix" ||
  pass "verify rejects a changed prefix"

ip -n ndp-host link set dev up0 allmulticast off
OUT=$(in_host "$BIN" ndp-proxy verify -uplink up0 -prefix "$PREFIX" -heal 2>&1) &&
  fail "verify exited zero despite drift" ||
  pass "verify exits non-zero on drift"
echo "$OUT" | grep -q "allmulti is not set" &&
  pass "verify names the drift" || fail "verify did not name the drift: $OUT"
echo "$OUT" | grep -q "pre-heal" &&
  pass "verify logs pre-heal counters" || fail "verify did not log pre-heal counters"
in_host "$BIN" ndp-proxy verify -uplink up0 -prefix "$PREFIX" >/dev/null &&
  pass "heal restored the attachment" || fail "heal did not restore the attachment"

# 11. Detach leaves nothing pinned behind.
in_host "$BIN" ndp-proxy detach
[ ! -e /sys/fs/bpf/ndp-proxy ] &&
  pass "detach removed the pins" || fail "detach left pins behind"

echo
if [ "$FAILURES" -eq 0 ]; then
  echo "all tests passed"
else
  echo "$FAILURES test(s) failed"
  exit 1
fi
