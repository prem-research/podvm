// SPDX-License-Identifier: Apache-2.0
/*
 * Per-container network policy on the container's cgroup. The agent loads one copy per enforced
 * container, with `policy` in a read-only map it freezes before load.
 * No BTF, CO-RE or kernel functions: the agent's loader resolves only `.rodata` and `maps`.
 */
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/types.h>

#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "the address and port constants below assume a little-endian BPF target"
#endif

#define SEC(name) __attribute__((section(name), used))
#define INLINE static inline __attribute__((always_inline))

/* Stops the compiler narrowing a context read or dropping a bounds check the verifier needs. */
#define barrier_var(var) __asm__ __volatile__("" : "+r"(var))

#define FIELD(expression)                 \
	({                                \
		__u32 value = (expression); \
		barrier_var(value);       \
		value;                    \
	})

#define BE32(value) ((__be32)__builtin_bswap32(value))
#define BE16(value) ((__be16)__builtin_bswap16(value))

#define ALLOW 1
#define DENY 0

#define AF_INET 2
#define AF_INET6 10
#define SOCK_STREAM 1
#define SOCK_DGRAM 2
/* The type field also carries SOCK_CLOEXEC and SOCK_NONBLOCK. */
#define SOCK_TYPE_MASK 0xf

/* `lo` is always ifindex 1 in a network namespace. */
#define LOOPBACK_IFINDEX 1

/* The agent's DNS filter, 127.0.0.53:53. */
#define DNS_STUB_ADDR BE32(0x7f000035)
#define DNS_STUB_PORT 53

/* Third word of ::ffff:a.b.c.d. */
#define V4_MAPPED BE32(0x0000ffff)
#define V6_LOOPBACK_TAIL BE32(0x00000001)

#define IPV4_HEADER_LEN 20
#define IPV6_HEADER_LEN 40
#define TCP_FLAGS_OFFSET 13
#define TCP_FLAGS_END 14
#define TCP_SYN 0x02
#define TCP_ACK 0x10
/* MF flag and fragment offset bits of `frag_off`. */
#define IPV4_FRAGMENT 0x3fff

/* ---------------------------------------------------------------------------------------------
 * Policy
 *
 * Keep in sync with `ProgramPolicy::encode` in net_policy.rs, which checks only the total size.
 * ------------------------------------------------------------------------------------------- */

#define MODE_LOOPBACK_ONLY 1
#define MODE_EGRESS_ALLOWLIST 2

/* One bit per port, indexed in host order. */
#define PORT_SET_BYTES 8192

/* `cidr_allow` is capped at 256 prefixes. */
#define MAX_CIDR4 256
#define MAX_CIDR6 256

/* Network byte order; an address matches when `addr & mask == net`. */
struct cidr4 {
	__be32 mask;
	__be32 net;
};

struct cidr6 {
	__be32 mask[4];
	__be32 net[4];
};

struct policy {
	/* MODE_*; anything else, all-zero included, denies. */
	__u32 mode;
	/* `cidr_allow` or `dns_allow` is set; otherwise ports alone decide. */
	__u32 constrained;
	/* `cidr_allow` contains 0.0.0.0/0 or ::/0. */
	__u32 any_v4;
	__u32 any_v6;
	__u32 cidr4_count;
	__u32 cidr6_count;
	/* This container's `service_ports`. */
	__u8 own_tcp[PORT_SET_BYTES];
	__u8 own_udp[PORT_SET_BYTES];
	/* Every container's service ports and the DNS stub port, whatever the protocol. */
	__u8 reserved[PORT_SET_BYTES];
	/* `port_allow`. */
	__u8 allow_tcp[PORT_SET_BYTES];
	__u8 allow_udp[PORT_SET_BYTES];
	struct cidr4 cidr4[MAX_CIDR4];
	struct cidr6 cidr6[MAX_CIDR6];
};

const volatile struct policy policy;

/*
 * Addresses the DNS filter resolved (IPv4 as ::ffff:a.b.c.d) to their `bpf_ktime_get_ns` expiry.
 * The agent creates and shares the map, and checks it against this definition.
 */
struct bpf_map_def {
	__u32 type;
	__u32 key_size;
	__u32 value_size;
	__u32 max_entries;
	__u32 map_flags;
};

struct bpf_map_def SEC("maps") resolved = {
	.type = BPF_MAP_TYPE_LRU_HASH,
	.key_size = 16,
	.value_size = 8,
	.max_entries = 1024,
};

static void *(*const bpf_map_lookup_elem)(void *map, const void *key) = (void *)BPF_FUNC_map_lookup_elem;
static __u64 (*const bpf_ktime_get_ns)(void) = (void *)BPF_FUNC_ktime_get_ns;

/* ---------------------------------------------------------------------------------------------
 * Shared rules
 * ------------------------------------------------------------------------------------------- */

INLINE int mode_is_valid(__u32 mode)
{
	return mode == MODE_LOOPBACK_ONLY || mode == MODE_EGRESS_ALLOWLIST;
}

INLINE int port_in(const volatile __u8 *set, __u32 port)
{
	__u32 byte = port >> 3;

	barrier_var(byte);
	byte &= PORT_SET_BYTES - 1;
	return (set[byte] >> (port & 7)) & 1;
}

INLINE int own_port(__u32 protocol, __u32 port)
{
	if (protocol == IPPROTO_TCP)
		return port_in(policy.own_tcp, port);
	if (protocol == IPPROTO_UDP)
		return port_in(policy.own_udp, port);
	return 0;
}

/* Matched by protocol: 443/tcp must not admit QUIC. */
INLINE int port_allowed(__u32 protocol, __u32 port)
{
	if (protocol == IPPROTO_TCP)
		return port_in(policy.allow_tcp, port);
	if (protocol == IPPROTO_UDP)
		return port_in(policy.allow_udp, port);
	return 0;
}

/* Default allow: NCCL, Gloo and ZMQ use ephemeral loopback ports. */
INLINE int loopback_rule(__u32 port)
{
	if (port_in(policy.own_tcp, port) || port_in(policy.own_udp, port))
		return ALLOW;
	if (port_in(policy.reserved, port))
		return DENY;
	return ALLOW;
}

INLINE int v4_is_loopback(__be32 ip)
{
	return (ip & BE32(0xff000000)) == BE32(0x7f000000);
}

/* The kernel delivers 0.0.0.0 on loopback, but no other address in 0.0.0.0/8. */
INLINE int v4_is_local_destination(__be32 ip)
{
	return ip == 0 || v4_is_loopback(ip);
}

/* `user_port` holds the port in network order in its low 16 bits. */
INLINE __u32 destination_port(struct bpf_sock_addr *ctx)
{
	__u32 port = FIELD(ctx->user_port);

	return ((port & 0xff) << 8) | ((port >> 8) & 0xff);
}

INLINE int is_resolved(const __be32 key[4])
{
	__u64 *expiry = bpf_map_lookup_elem(&resolved, key);

	if (!expiry)
		return 0;
	return *expiry > bpf_ktime_get_ns();
}

/* ---------------------------------------------------------------------------------------------
 * connect() and UDP sendmsg(), IPv4
 * ------------------------------------------------------------------------------------------- */

INLINE int destination4_allowed(__be32 ip)
{
	__be32 key[4] = { 0, 0, V4_MAPPED, ip };
	__u32 index;

	if (!policy.constrained || policy.any_v4)
		return 1;
	for (index = 0; index < MAX_CIDR4; index++) {
		if (index >= policy.cidr4_count)
			break;
		if ((ip & policy.cidr4[index].mask) == policy.cidr4[index].net)
			return 1;
	}
	return is_resolved(key);
}

SEC("netpol/outbound4")
int outbound4(struct bpf_sock_addr *ctx)
{
	__u32 mode = policy.mode;
	__be32 ip;
	__u32 port;

	if (!mode_is_valid(mode))
		return DENY;
	if (FIELD(ctx->user_family) != AF_INET)
		return DENY;
	ip = FIELD(ctx->user_ip4);
	port = destination_port(ctx);

	/* Before the local rule, which denies the stub port as reserved. */
	if (mode == MODE_EGRESS_ALLOWLIST && ip == DNS_STUB_ADDR && port == DNS_STUB_PORT)
		return ALLOW;
	if (v4_is_local_destination(ip))
		return loopback_rule(port);
	if (mode == MODE_LOOPBACK_ONLY)
		return DENY;

	if (!port_allowed(FIELD(ctx->protocol), port))
		return DENY;
	return destination4_allowed(ip) ? ALLOW : DENY;
}

/* ---------------------------------------------------------------------------------------------
 * connect() and UDP sendmsg(), IPv6
 *
 * The verifier refuses `user_ip4` on the IPv6 hooks.
 * ------------------------------------------------------------------------------------------- */

INLINE int destination6_allowed(const __be32 ip[4])
{
	__be32 key[4] = { ip[0], ip[1], ip[2], ip[3] };
	__u32 index;

	if (!policy.constrained || policy.any_v6)
		return 1;
	for (index = 0; index < MAX_CIDR6; index++) {
		const volatile struct cidr6 *prefix = &policy.cidr6[index];
		__u32 difference;

		if (index >= policy.cidr6_count)
			break;
		/* One branch per prefix, not per word, to keep the verifier's path count down. */
		difference = ((ip[0] & prefix->mask[0]) ^ prefix->net[0]) |
			     ((ip[1] & prefix->mask[1]) ^ prefix->net[1]) |
			     ((ip[2] & prefix->mask[2]) ^ prefix->net[2]) |
			     ((ip[3] & prefix->mask[3]) ^ prefix->net[3]);
		barrier_var(difference);
		if (!difference)
			return 1;
	}
	return is_resolved(key);
}

SEC("netpol/outbound6")
int outbound6(struct bpf_sock_addr *ctx)
{
	__u32 mode = policy.mode;
	__be32 ip[4];
	__u32 port;
	int local = 0;
	int mapped = 0;

	if (!mode_is_valid(mode))
		return DENY;
	if (FIELD(ctx->user_family) != AF_INET6)
		return DENY;
	port = destination_port(ctx);
	ip[0] = FIELD(ctx->user_ip6[0]);
	ip[1] = FIELD(ctx->user_ip6[1]);
	ip[2] = FIELD(ctx->user_ip6[2]);
	ip[3] = FIELD(ctx->user_ip6[3]);

	if (ip[0] == 0 && ip[1] == 0) {
		if (ip[2] == V4_MAPPED) {
			mapped = 1;
			if (mode == MODE_EGRESS_ALLOWLIST && ip[3] == DNS_STUB_ADDR && port == DNS_STUB_PORT)
				return ALLOW;
			local = v4_is_local_destination(ip[3]);
		} else if (ip[2] == 0) {
			local = ip[3] == 0 || ip[3] == V6_LOOPBACK_TAIL;
		}
	}
	if (local)
		return loopback_rule(port);
	if (mode == MODE_LOOPBACK_ONLY)
		return DENY;

	if (!port_allowed(FIELD(ctx->protocol), port))
		return DENY;
	/* The kernel sends to ::ffff:a.b.c.d over IPv4, so IPv4 prefixes decide, not ::/0. */
	if (mapped)
		return destination4_allowed(ip[3]) ? ALLOW : DENY;
	return destination6_allowed(ip) ? ALLOW : DENY;
}

/* ---------------------------------------------------------------------------------------------
 * bind()
 *
 * Off loopback, only own service ports may bind. 0.0.0.0 and :: are wildcards here, not local.
 * ------------------------------------------------------------------------------------------- */

INLINE int bind_verdict(struct bpf_sock_addr *ctx, int loopback)
{
	__u32 port = destination_port(ctx);

	if (own_port(FIELD(ctx->protocol), port))
		return ALLOW;
	if (!loopback)
		return DENY;
	/* No squatting on another container's service port or the DNS stub's. */
	if (port_in(policy.reserved, port))
		return DENY;
	return ALLOW;
}

SEC("netpol/bind4")
int bind4(struct bpf_sock_addr *ctx)
{
	if (!mode_is_valid(policy.mode))
		return DENY;
	if (FIELD(ctx->user_family) != AF_INET)
		return DENY;
	return bind_verdict(ctx, v4_is_loopback(FIELD(ctx->user_ip4)));
}

SEC("netpol/bind6")
int bind6(struct bpf_sock_addr *ctx)
{
	__be32 ip[4];
	int loopback = 0;

	if (!mode_is_valid(policy.mode))
		return DENY;
	if (FIELD(ctx->user_family) != AF_INET6)
		return DENY;
	ip[0] = FIELD(ctx->user_ip6[0]);
	ip[1] = FIELD(ctx->user_ip6[1]);
	ip[2] = FIELD(ctx->user_ip6[2]);
	ip[3] = FIELD(ctx->user_ip6[3]);

	if (ip[0] == 0 && ip[1] == 0) {
		if (ip[2] == V4_MAPPED)
			loopback = v4_is_loopback(ip[3]);
		else if (ip[2] == 0)
			loopback = ip[3] == V6_LOOPBACK_TAIL;
	}
	return bind_verdict(ctx, loopback);
}

/* ---------------------------------------------------------------------------------------------
 * socket()
 *
 * TCP and UDP only: ping sockets (SOCK_DGRAM, IPPROTO_ICMP) escape the UDP sendmsg hooks.
 * ------------------------------------------------------------------------------------------- */

SEC("netpol/sock_create")
int sock_create(struct bpf_sock *sk)
{
	__u32 family = FIELD(sk->family);
	__u32 type = FIELD(sk->type) & SOCK_TYPE_MASK;
	__u32 protocol = FIELD(sk->protocol);

	if (family != AF_INET && family != AF_INET6)
		return DENY;
	if (type == SOCK_STREAM)
		return protocol == 0 || protocol == IPPROTO_TCP;
	if (type == SOCK_DGRAM)
		return protocol == 0 || protocol == IPPROTO_UDP;
	return DENY;
}

/* ---------------------------------------------------------------------------------------------
 * Packet-level backstop on egress, for what the socket hooks cannot see:
 * - source routing (IPv4 options, IPv6 extension headers) past the checked destination;
 * - a forced device (SO_BINDTODEVICE, IP_PKTINFO, ...) taking a local destination off `lo`;
 * - listen() auto-binding a port without the bind hook: SYN-ACKs must come from service ports.
 * ------------------------------------------------------------------------------------------- */

/* TCP and UDP both start with the source port. */
INLINE __u32 source_port(const __u8 *transport)
{
	return ((__u32)transport[0] << 8) | transport[1];
}

/* Loopback-only, off `lo`: only replies from own service ports leave the guest. */
INLINE int own_source_port(__u32 protocol, const __u8 *transport, const __u8 *end)
{
	if (transport + 2 > end)
		return DENY;
	return own_port(protocol, source_port(transport)) ? ALLOW : DENY;
}

INLINE int listener_check(const __u8 *tcp, const __u8 *end)
{
	const __u8 syn_ack = TCP_SYN | TCP_ACK;

	if (tcp + TCP_FLAGS_END > end)
		return DENY;
	if ((tcp[TCP_FLAGS_OFFSET] & syn_ack) != syn_ack)
		return ALLOW;
	return port_in(policy.own_tcp, source_port(tcp)) ? ALLOW : DENY;
}

INLINE int backstop4(const __u8 *packet, const __u8 *end, int on_loopback, int loopback_only)
{
	const struct iphdr *ip = (const void *)packet;
	const __u8 *transport = packet + IPV4_HEADER_LEN;

	/* IHL must be 5: no options. */
	if ((packet[0] & 0x0f) != 5)
		return DENY;
	if (transport > end)
		return DENY;

	if (!on_loopback) {
		/* A local destination only gets here through a forced device. */
		if (v4_is_local_destination(ip->daddr))
			return DENY;
		if (loopback_only) {
			/* Fragments carry no ports. */
			if (ip->frag_off & BE16(IPV4_FRAGMENT))
				return DENY;
			return own_source_port(ip->protocol, transport, end);
		}
	}

	if (ip->protocol != IPPROTO_TCP)
		return ALLOW;
	if (v4_is_loopback(ip->daddr))
		return ALLOW;
	return listener_check(transport, end);
}

INLINE int backstop6(const __u8 *packet, const __u8 *end, int on_loopback, int loopback_only)
{
	const struct ipv6hdr *ip = (const void *)packet;
	const __u8 *transport = packet + IPV6_HEADER_LEN;
	__be32 destination[4];

	if (transport > end)
		return DENY;
	destination[0] = ip->daddr.s6_addr32[0];
	destination[1] = ip->daddr.s6_addr32[1];
	destination[2] = ip->daddr.s6_addr32[2];
	destination[3] = ip->daddr.s6_addr32[3];

	if (!on_loopback) {
		/* ::, ::1 and IPv4-mapped destinations never belong on a wire. */
		if (destination[0] == 0 && destination[1] == 0) {
			if (destination[2] == V4_MAPPED)
				return DENY;
			if (destination[2] == 0 && (destination[3] == 0 || destination[3] == V6_LOOPBACK_TAIL))
				return DENY;
		}
		/* own_port() refuses anything but TCP and UDP, fragments included. */
		if (loopback_only)
			return own_source_port(ip->nexthdr, transport, end);
	}

	/* Fragment headers pass: a routing header would have to precede them. */
	if (ip->nexthdr == IPPROTO_UDP || ip->nexthdr == IPPROTO_FRAGMENT)
		return ALLOW;
	if (ip->nexthdr != IPPROTO_TCP)
		return DENY;
	if (destination[0] == 0 && destination[1] == 0 && destination[2] == 0 &&
	    destination[3] == V6_LOOPBACK_TAIL)
		return ALLOW;
	return listener_check(transport, end);
}

SEC("netpol/egress")
int egress(struct __sk_buff *skb)
{
	const __u8 *packet = (const void *)(long)skb->data;
	const __u8 *end = (const void *)(long)skb->data_end;
	int on_loopback = FIELD(skb->ifindex) == LOOPBACK_IFINDEX;
	__u32 mode = policy.mode;
	__u8 version;

	if (!mode_is_valid(mode))
		return DENY;
	if (packet + 1 > end)
		return DENY;
	version = packet[0] >> 4;
	if (version == 6)
		return backstop6(packet, end, on_loopback, mode == MODE_LOOPBACK_ONLY);
	if (version != 4)
		return DENY;
	return backstop4(packet, end, on_loopback, mode == MODE_LOOPBACK_ONLY);
}

char program_license[] SEC("license") = "GPL";
