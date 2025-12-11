// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* eBPF program to detect packets to specific IPs and notify userspace.
 * Supports multiple target IPs with per-IP debouncing. */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "packet_filter.h"

#define TC_ACT_OK 0
#define ETH_P_IP 0x0800
#define MAX_IPS 64

/* Hash map of target IPs to watch - key is IP, value is unused (just for existence check) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_IPS);
    __type(key, __u32);    /* IP address in network byte order */
    __type(value, __u8);   /* dummy value, we just check existence */
} target_ips SEC(".maps");

/* Debounce interval in nanoseconds */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, __u64);
} debounce_config SEC(".maps");

/* Last event timestamp per IP for debouncing */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_IPS);
    __type(key, __u32);    /* IP address */
    __type(value, __u64);  /* last event timestamp */
} last_event_ts SEC(".maps");

/* Ring buffer for events */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024);
} events SEC(".maps");

SEC("tc")
int packet_filter_egress(struct __sk_buff *ctx) {
    void *data_end = (void *)(__u64)ctx->data_end;
    void *data = (void *)(__u64)ctx->data;
    struct iphdr *ip = data;
    int key = 0;
    __u64 *debounce_ns, *last_ts, now;
    __u8 *exists;

    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    /* Check if raw IP (L3) or Ethernet (L2) */
    __u8 version = (*((__u8 *)data)) >> 4;
    if (version != 4) {
        if (ctx->protocol != bpf_htons(ETH_P_IP))
            return TC_ACT_OK;
        struct ethhdr *eth = data;
        if ((void *)(eth + 1) > data_end)
            return TC_ACT_OK;
        ip = (struct iphdr *)(eth + 1);
        if ((void *)(ip + 1) > data_end)
            return TC_ACT_OK;
    }

    /* Check if destination IP is in our watch list */
    exists = bpf_map_lookup_elem(&target_ips, &ip->daddr);
    if (!exists)
        return TC_ACT_OK;

    /* Debounce check - per IP */
    now = bpf_ktime_get_ns();
    debounce_ns = bpf_map_lookup_elem(&debounce_config, &key);
    last_ts = bpf_map_lookup_elem(&last_event_ts, &ip->daddr);

    if (last_ts && debounce_ns && *debounce_ns > 0) {
        if (now - *last_ts < *debounce_ns)
            return TC_ACT_OK; /* Still in debounce period for this IP */
    }

    /* Update last event timestamp for this IP */
    bpf_map_update_elem(&last_event_ts, &ip->daddr, &now, BPF_ANY);

    /* Send event */
    struct packet_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return TC_ACT_OK;

    e->dst_ip = ip->daddr;
    e->ts = now;
    bpf_ringbuf_submit(e, 0);

    return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";
