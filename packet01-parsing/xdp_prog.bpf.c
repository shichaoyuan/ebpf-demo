#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
/* Defines xdp_stats_map from packet04 */
#include "xdp_stats_kern_user.h"
#include "xdp_stats_kern.h"

#define ETH_P_IPV6	0x86DD /* Ethernet type for IPv6 */
#define IPPROTO_ICMPV6	58 /* IPv6 protocol number for ICMPv6 */
#define ICMPV6_ECHO_REQUEST	128 /* ICMPv6 type for Echo Request */

#define icmp6_sequence	icmp6_dataun.u_echo.sequence

/* Header cursor to keep track of current parsing position */
struct hdr_cursor {
	void *pos;
};

/* Packet parsing helpers.
 *
 * Each helper parses a packet header, including doing bounds checking, and
 * returns the type of its contents if successful, and -1 otherwise.
 *
 * For Ethernet and IP headers, the content type is the type of the payload
 * (h_proto for Ethernet, nexthdr for IPv6), for ICMP it is the ICMP type field.
 * All return values are in network byte order.
 */
static __always_inline int parse_ethhdr(struct hdr_cursor *nh,
					void *data_end,
					struct ethhdr **ethhdr)
{
	struct ethhdr *eth = nh->pos;
	int hdrsize = sizeof(*eth);

	/* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */
	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*ethhdr = eth;

	return eth->h_proto; /* network-byte-order */
}

static __always_inline int parse_ip6hdr(struct hdr_cursor *nh,
					void *data_end,
					struct ipv6hdr **ip6hdr)
{
	struct ipv6hdr *ip6 = nh->pos;

	if (ip6 + 1 > data_end)
		return -1;

	nh->pos = ip6 + 1;
	*ip6hdr = ip6;

	return ip6->nexthdr;
}

static __always_inline int parse_icmp6hdr(struct hdr_cursor *nh,
					  void *data_end,
					  struct icmp6hdr **icmp6hdr)
{
	struct icmp6hdr *icmp6 = nh->pos;
	if (icmp6 + 1 > data_end)
		return -1;

	nh->pos = icmp6 + 1;
	*icmp6hdr = icmp6;

	return icmp6->icmp6_type;
}

SEC("xdp")
int  xdp_parser_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth;

	/* Default action XDP_PASS, imply everything we couldn't parse, or that
	 * we don't want to deal with, we just pass up the stack and let the
	 * kernel deal with it.
	 */
	__u32 action = XDP_PASS; /* Default action */

        /* These keep track of the next header type and iterator pointer */
	struct hdr_cursor nh;
	int nh_type;

	/* Start next header cursor position at data start */
	nh.pos = data;

	/* Packet parsing in steps: Get each header one at a time, aborting if
	 * parsing fails. Each helper function does sanity checking (is the
	 * header type in the packet correct?), and bounds checking.
	 */
	nh_type = parse_ethhdr(&nh, data_end, &eth);
	if (nh_type != bpf_htons(ETH_P_IPV6))
		goto out;

	struct ipv6hdr *ip6;
	int ip_type;
	ip_type = parse_ip6hdr(&nh, data_end, &ip6);
	if (ip_type != IPPROTO_ICMPV6)
		goto out;

	struct icmp6hdr *icmp6;
	int icmp_type;
	icmp_type = parse_icmp6hdr(&nh, data_end, &icmp6);
	if (icmp_type != ICMPV6_ECHO_REQUEST)
		goto out;

	if (bpf_ntohs(icmp6->icmp6_sequence) % 2)
		goto out;

	action = XDP_DROP;
out:
	return xdp_stats_record_action(ctx, action); /* read via xdp_stats */
}

char _license[] SEC("license") = "GPL";