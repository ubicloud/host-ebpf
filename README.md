# host-ebpf

eBPF programs for Ubicloud hypervisor hosts, and the loader that configures
them. Rhizome installs the released binary and drives it from systemd units;
everything below the command line -- the C programs, their map layouts, and
the code that writes those maps -- lives here, so a layout change is never
split across two repositories.

## Programs

### ndp-proxy

Answers IPv6 Neighbor Solicitations for addresses routed off the uplink into
VM network namespaces, giving NDP the routing-driven behavior that proxy ARP
has had for IPv4 all along.

Some providers deliver a host's IPv6 network on-link: their router solicits
for every individual destination address and only forwards after an
advertisement. Ubicloud configures none of a VM's addresses on a host
interface -- they exist only as routes into the VM's namespace -- so the
kernel answers for none of them. Linux's `proxy_ndp` is an exact-match /128
registry, which would force the control plane to enumerate every address a
guest might use.

Instead, a program on the uplink's tc ingress hook runs the kernel's own FIB
lookup per solicitation and answers when the target routes off some other
interface:

```
NS "who has T?"  ->  bpf_fib_lookup(T)  ->  egress != uplink?  ->  NA "T is at <uplink MAC>"
                                        ->  anything else      ->  pass to the kernel stack
```

For a host holding `2001:db8:aa::/64`:

| NS target                | best FIB match            | action |
|--------------------------|---------------------------|--------|
| addr in a live VM's /79  | `/79 dev vetho<vm>`       | answer |
| unallocated addr in /64  | on-link /64 on the uplink | silent |
| host's own address       | local (`NOT_FWDED`)       | silent; the kernel answers |
| anything else            | default route (uplink)    | silent |

The routing table is the only registry, so a guest may use any address in its
delegated prefix with no per-address bookkeeping anywhere. An LPM map holding
the host's own network bounds what the program may ever answer, independent
of FIB contents.

Protocol handling matches the kernel responder it preempts: solicitations are
ignored unless the hop limit is 255 (RFC 4861 7.1.1) and the ICMPv6 checksum
verifies; duplicate address detection is never defended, so a node that
legitimately holds an address can still claim it; advertisements carry
Router|Solicited with Override clear (RFC 4861 7.2.4, so a real owner wins
the neighbor cache) and are sourced from the target. The program never drops
a packet -- every non-answer path returns `TC_ACT_UNSPEC`.

The uplink is put in allmulticast mode because the first solicitation for a
target arrives on a solicited-node multicast group derived from its low 24
bits, which cannot be joined ahead of time for a whole prefix; without it the
NIC discards those frames before any hook runs.

Answers are capped at 5000/s host-wide. Each advertisement answers one
solicitation, so this bounds reflection rather than amplification.

## Usage

```
host-ebpf ndp-proxy apply    -uplink eth0 -prefix 2001:db8:aa::/64
host-ebpf ndp-proxy verify   -uplink eth0 -prefix 2001:db8:aa::/64 [-heal]
host-ebpf ndp-proxy counters [-json]
host-ebpf ndp-proxy detach
```

`apply` is safe to call repeatedly, but it is not idempotent: every call
loads a fresh program and maps, so counters always restart from zero, even
when reapplying the same uplink and prefix. When a previous attachment
already exists on the requested uplink, `apply` swaps the new program into
it in place -- TCX links support updating the attached program without
detaching, so solicitations keep being answered throughout. It only falls
back to detaching and reattaching from scratch, with a brief window where
solicitations go unanswered, when there is no usable existing attachment to
update (first run on a host, or one whose uplink changed).

`verify` exits non-zero when the attachment has drifted, naming what
drifted and printing the counters it is about to lose; with `-heal` it
re-applies first. Program and maps are pinned under `/sys/fs/bpf/ndp-proxy`;
neither pins nor attachments survive a reboot, so whatever installs this
must re-run `apply` at boot.

Requires kernel 6.6 or newer: `BPF_FIB_LOOKUP_SKIP_NEIGH` landed in 6.4 and
TCX links in 6.6.

## Development

```
make          # compile the BPF object, then the binary
make test     # go vet, unit tests, and the integration rig (needs root)
```

`make` compiles `ndp_proxy.bpf.c` and embeds the result into the binary. The
object is a build artifact rather than a committed one, so what ships is
always derived from the source in the same commit; `go build` on its own
will fail until `make` has produced it. The Go unit tests assert that the
map key/value sizes and counter count still match the compiled object,
which is what keeps the loader's structs honest.

`test/run_tests.sh` builds two network namespaces -- a simulated on-link
provider router and a host with a stub `vetho` carrying a delegated /79 --
and drives the real binary, asserting each row of the table above on the
wire along with the drift, heal, and detach behavior.
