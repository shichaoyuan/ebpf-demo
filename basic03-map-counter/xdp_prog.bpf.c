#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "common_kern_user.h"

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct datarec);
	__uint(max_entries, XDP_ACTION_MAX);

} xdp_stats_map SEC(".maps");

#ifndef lock_xadd
#define lock_xadd(ptr, val) ((void) __sync_fetch_and_add(ptr, val))
#endif

SEC("xdp")
int  xdp_stats1_func(struct xdp_md *ctx)
{
	struct datarec *rec;
	__u32 key = XDP_PASS;

	rec = bpf_map_lookup_elem(&xdp_stats_map, &key);

	if (!rec)
		return XDP_ABORTED;

	lock_xadd(&rec->rx_packets, 1);

	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;
	__u64 bytes = data_end - data;
	lock_xadd(&rec->rx_bytes, bytes);

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";