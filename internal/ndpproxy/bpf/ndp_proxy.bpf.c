/* Route-following NDP proxy for delegated VM prefixes.
 *
 * Attached to clsact ingress on the uplink of hosts whose provider
 * treats the host's IPv6 network as on-link (vm_host.ndp_needed).
 * Answers a Neighbor Solicitation iff the target's FIB lookup egresses
 * an interface other than the uplink, i.e. the address is routed into
 * a VM's network namespace. Every non-answer path returns TC_ACT_UNSPEC
 * so the kernel stack still sees the solicitation.
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define AF_INET6 10
#define IPPROTO_ICMPV6 58
#define ND_NEIGHBOR_SOLICIT 135
#define ND_NEIGHBOR_ADVERT 136

/* Index order is mirrored by COUNTER_NAMES in
 * rhizome/host/lib/ndp_proxy_setup.rb. */
enum ndp_counter {
	COUNTER_SEEN_NS,
	COUNTER_ANSWERED,
	COUNTER_PASS_MALFORMED,
	COUNTER_PASS_DAD,
	COUNTER_PASS_PREFIX_MISS,
	COUNTER_PASS_FIB_LOCAL,
	COUNTER_PASS_FIB_UPLINK,
	COUNTER_RATELIMITED,
	COUNTER_MAX,
};

struct ndp_cfg {
	__u32 uplink_ifindex;
	__u8 uplink_mac[6];
	__u16 pad;
};

struct lpm_key {
	__u32 prefixlen;
	__u8 addr[16];
};

struct rate_state {
	__u64 window;
	__u64 count;
};

/* Answers per ~1.07s window, host-wide. */
#define RATE_LIMIT_WINDOW 5000

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct ndp_cfg);
} cfg SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 16);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct lpm_key);
	__type(value, __u8);
} cfg_prefixes SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, COUNTER_MAX);
	__type(key, __u32);
	__type(value, __u64);
} counters SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct rate_state);
} rate SEC(".maps");

struct ns_msg {
	__u8 icmp_type;
	__u8 icmp_code;
	__be16 cksum;
	__be32 flags;
	struct in6_addr target;
} __attribute__((packed));

static __always_inline void count(__u32 idx)
{
	__u64 *v = bpf_map_lookup_elem(&counters, &idx);

	if (v)
		(*v)++;
}

static __always_inline __u32 sum16(const __u8 *buf, int len, __u32 acc)
{
	int i;

	for (i = 0; i < len; i += 2)
		acc += ((__u32)buf[i] << 8) | buf[i + 1];
	return acc;
}

static __always_inline int ratelimited(void)
{
	__u32 zero = 0;
	struct rate_state *rs = bpf_map_lookup_elem(&rate, &zero);
	__u64 window = bpf_ktime_get_ns() >> 30;

	if (!rs)
		return 1;
	/* Racing resets only fuzz the window boundary; the count itself is
	 * atomic so the budget holds regardless of how many CPUs answer. */
	if (rs->window != window) {
		rs->window = window;
		rs->count = 0;
	}
	return __sync_fetch_and_add(&rs->count, 1) >= RATE_LIMIT_WINDOW;
}

SEC("tc")
int ndp_proxy(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ethhdr *eth = data;
	struct ipv6hdr *ip6;
	struct ns_msg *ns;
	struct ndp_cfg *c;
	struct lpm_key lk = {.prefixlen = 128};
	struct bpf_fib_lookup fib = {};
	__u32 zero = 0;
	__u16 plen;
	int icmp_len, i;
	long rc;
	__u32 sum;
	__u16 cksum;
	__u8 na[32];
	__u8 ph[40];
	__u8 orig_eth_src[6];
	__u8 mac[6];

	if ((void *)(eth + 1) > data_end)
		return TC_ACT_UNSPEC;
	if (eth->h_proto != bpf_htons(ETH_P_IPV6))
		return TC_ACT_UNSPEC;

	ip6 = (void *)(eth + 1);
	if ((void *)(ip6 + 1) > data_end)
		return TC_ACT_UNSPEC;
	if (ip6->nexthdr != IPPROTO_ICMPV6)
		return TC_ACT_UNSPEC;

	ns = (void *)(ip6 + 1);
	if ((void *)(ns + 1) > data_end)
		return TC_ACT_UNSPEC;
	if (ns->icmp_type != ND_NEIGHBOR_SOLICIT || ns->icmp_code != 0)
		return TC_ACT_UNSPEC;

	count(COUNTER_SEEN_NS);

	/* RFC 4861 7.1.1: NS with hop limit != 255 crossed a router. */
	if (ip6->version != 6 || ip6->hop_limit != 255) {
		count(COUNTER_PASS_MALFORMED);
		return TC_ACT_UNSPEC;
	}

	/* Unspecified source is duplicate address detection; never defend
	 * (may carry an RFC 7527 nonce option, so classify before shape). */
	if (!(ip6->saddr.s6_addr32[0] | ip6->saddr.s6_addr32[1] |
	      ip6->saddr.s6_addr32[2] | ip6->saddr.s6_addr32[3])) {
		count(COUNTER_PASS_DAD);
		return TC_ACT_UNSPEC;
	}

	plen = bpf_ntohs(ip6->payload_len);
	if ((plen != 24 && plen != 32) ||
	    ns->target.s6_addr[0] == 0xff ||
	    ip6->saddr.s6_addr[0] == 0xff) {
		count(COUNTER_PASS_MALFORMED);
		return TC_ACT_UNSPEC;
	}
	if (plen == 32) {
		__u8 *opt = (__u8 *)(ns + 1);

		if ((void *)(opt + 8) > data_end || opt[0] != 1 || opt[1] != 1) {
			count(COUNTER_PASS_MALFORMED);
			return TC_ACT_UNSPEC;
		}
	} else if (ip6->daddr.s6_addr[0] == 0xff) {
		/* RFC 4861 7.2.4: an advertisement answering a multicast
		 * solicitation must carry a target link-layer option, which
		 * only fits in place of a source link-layer option. */
		count(COUNTER_PASS_MALFORMED);
		return TC_ACT_UNSPEC;
	}

	/* RFC 4861 7.1.1: the kernel responder this preempts drops
	 * solicitations whose checksum does not verify. */
	__builtin_memcpy(ph, &ip6->saddr, 16);
	__builtin_memcpy(ph + 16, &ip6->daddr, 16);
	for (i = 32; i < 39; i++)
		ph[i] = 0;
	ph[35] = plen;
	ph[39] = IPPROTO_ICMPV6;
	sum = sum16(ph, 40, 0);
	if (plen == 32) {
		/* The verifier tracks bounds per register, so the option check
		 * above does not carry over to summing from ns. */
		if ((void *)((__u8 *)ns + 32) > data_end) {
			count(COUNTER_PASS_MALFORMED);
			return TC_ACT_UNSPEC;
		}
		sum = sum16((__u8 *)ns, 32, sum);
	} else {
		sum = sum16((__u8 *)ns, 24, sum);
	}
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	if ((__u16)sum != 0xffff) {
		count(COUNTER_PASS_MALFORMED);
		return TC_ACT_UNSPEC;
	}

	__builtin_memcpy(lk.addr, &ns->target, 16);
	if (!bpf_map_lookup_elem(&cfg_prefixes, &lk)) {
		count(COUNTER_PASS_PREFIX_MISS);
		return TC_ACT_UNSPEC;
	}

	c = bpf_map_lookup_elem(&cfg, &zero);
	if (!c || !c->uplink_ifindex)
		return TC_ACT_UNSPEC;

	fib.family = AF_INET6;
	fib.ifindex = c->uplink_ifindex;
	__builtin_memcpy(fib.ipv6_dst, &ns->target, 16);
	rc = bpf_fib_lookup(skb, &fib, sizeof(fib), BPF_FIB_LOOKUP_SKIP_NEIGH);
	if (rc == BPF_FIB_LKUP_RET_NOT_FWDED) {
		count(COUNTER_PASS_FIB_LOCAL);
		return TC_ACT_UNSPEC;
	}
	if (rc != BPF_FIB_LKUP_RET_SUCCESS || fib.ifindex == c->uplink_ifindex) {
		count(COUNTER_PASS_FIB_UPLINK);
		return TC_ACT_UNSPEC;
	}

	if (ratelimited()) {
		count(COUNTER_RATELIMITED);
		return TC_ACT_UNSPEC;
	}

	__builtin_memcpy(orig_eth_src, eth->h_source, 6);
	__builtin_memcpy(mac, c->uplink_mac, 6);

	na[0] = ND_NEIGHBOR_ADVERT;
	na[1] = 0;
	na[2] = 0;
	na[3] = 0;
	/* Router|Solicited. RFC 4861 7.2.4: a proxy leaves Override clear so
	 * an actual owner of the address still wins the neighbor cache. */
	na[4] = 0xc0;
	na[5] = 0;
	na[6] = 0;
	na[7] = 0;
	__builtin_memcpy(na + 8, &ns->target, 16);
	icmp_len = 24;
	if (plen == 32) {
		na[24] = 2;
		na[25] = 1;
		__builtin_memcpy(na + 26, mac, 6);
		icmp_len = 32;
	}

	/* ICMPv6 checksum over the IPv6 pseudo-header (RFC 8200 8.1):
	 * NA source is the target (RFC 4861 7.2.4), NA destination the
	 * soliciting address. */
	__builtin_memcpy(ph, na + 8, 16);
	__builtin_memcpy(ph + 16, &ip6->saddr, 16);
	for (i = 32; i < 39; i++)
		ph[i] = 0;
	ph[35] = icmp_len;
	ph[39] = IPPROTO_ICMPV6;
	sum = sum16(ph, 40, 0);
	sum = (plen == 32) ? sum16(na, 32, sum) : sum16(na, 24, sum);
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	cksum = ~sum;
	na[2] = cksum >> 8;
	na[3] = cksum & 0xff;

	if (bpf_skb_store_bytes(skb, 0, orig_eth_src, 6, 0) ||
	    bpf_skb_store_bytes(skb, 6, mac, 6, 0) ||
	    bpf_skb_store_bytes(skb, 22, na + 8, 16, 0) ||
	    bpf_skb_store_bytes(skb, 38, ph + 16, 16, 0))
		return TC_ACT_UNSPEC;
	rc = (plen == 32) ? bpf_skb_store_bytes(skb, 54, na, 32, 0) :
			    bpf_skb_store_bytes(skb, 54, na, 24, 0);
	if (rc)
		return TC_ACT_UNSPEC;

	count(COUNTER_ANSWERED);
	return bpf_redirect(c->uplink_ifindex, 0);
}

char LICENSE[] SEC("license") = "GPL";
