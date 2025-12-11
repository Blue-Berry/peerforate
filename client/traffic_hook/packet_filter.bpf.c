// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* eBPF program to detect packets to specific IP subnets and notify userspace.
 * Supports multiple target subnets (IPv4 and IPv6) using LPM Trie. */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "packet_filter.h"

#define TC_ACT_OK 0
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define MAX_IPS 256

/* Key structures for LPM Trie */
struct ipv4_lpm_key {
    __u32 prefixlen;
    __u32 data;
};

struct ipv6_lpm_key {
    __u32 prefixlen;
    struct in6_addr data;
};

/* IPv4 target IPs (LPM Trie) */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, MAX_IPS);
    __type(key, struct ipv4_lpm_key);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} target_ips_v4 SEC(".maps");

/* IPv6 target IPs (LPM Trie) */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, MAX_IPS);
    __type(key, struct ipv6_lpm_key);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} target_ips_v6 SEC(".maps");

/* Debounce interval in nanoseconds */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, __u64);
} debounce_config SEC(".maps");

/* Last event timestamp per IP (IPv4) - still HASH because we track per-exact-IP */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u64);
} last_event_ts_v4 SEC(".maps");

/* Last event timestamp per IP (IPv6) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct in6_addr);
    __type(value, __u64);
} last_event_ts_v6 SEC(".maps");

/* Ring buffer for events */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024);
} events SEC(".maps");

static __always_inline void send_event(void *ip_addr, int version, __u64 now) {
    struct packet_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return;

    e->version = version;
    e->ts = now;
    e->_pad = 0;
    
    if (version == 4) {
        __builtin_memset(e->dst_ip, 0, 16);
        __builtin_memcpy(e->dst_ip, ip_addr, 4);
    } else {
        __builtin_memcpy(e->dst_ip, ip_addr, 16);
    }
    
    bpf_ringbuf_submit(e, 0);
}

SEC("tc")
int packet_filter_egress(struct __sk_buff *ctx) {
    void *data_end = (void *)(__u64)ctx->data_end;
    void *data = (void *)(__u64)ctx->data;
    
    struct iphdr *ip4 = NULL;
    struct ipv6hdr *ip6 = NULL;
    int version = 0;

    /* Check protocol and parse header */
    if ((void *)(data + 1) > data_end)
        return TC_ACT_OK;

    __u8 first_byte = *((__u8 *)data);
    __u8 ip_version = first_byte >> 4;

    /* Handle Layer 3 (raw IP) */
    if (ip_version == 4) {
        ip4 = (struct iphdr *)data;
        if ((void *)(ip4 + 1) > data_end) return TC_ACT_OK;
        version = 4;
    } else if (ip_version == 6) {
        ip6 = (struct ipv6hdr *)data;
        if ((void *)(ip6 + 1) > data_end) return TC_ACT_OK;
        version = 6;
    } else {
        /* Handle Layer 2 (Ethernet) */
        struct ethhdr *eth = data;
        if ((void *)(eth + 1) > data_end) return TC_ACT_OK;
        
        if (ctx->protocol == bpf_htons(ETH_P_IP)) {
            ip4 = (struct iphdr *)(eth + 1);
            if ((void *)(ip4 + 1) > data_end) return TC_ACT_OK;
            version = 4;
        } else if (ctx->protocol == bpf_htons(ETH_P_IPV6)) {
            ip6 = (struct ipv6hdr *)(eth + 1);
            if ((void *)(ip6 + 1) > data_end) return TC_ACT_OK;
            version = 6;
        } else {
            return TC_ACT_OK;
        }
    }

    int key = 0;
    __u64 *debounce_ns = bpf_map_lookup_elem(&debounce_config, &key);
    __u64 now = bpf_ktime_get_ns();
    __u64 *last_ts;
    __u8 *exists;

    if (version == 4) {
        struct ipv4_lpm_key lpm_key = { .prefixlen = 32, .data = ip4->daddr };
        exists = bpf_map_lookup_elem(&target_ips_v4, &lpm_key);
        if (!exists) {
             // bpf_printk("IP %x not in map", bpf_ntohl(ip4->daddr));
             return TC_ACT_OK;
        }

        last_ts = bpf_map_lookup_elem(&last_event_ts_v4, &ip4->daddr);
        if (last_ts && debounce_ns && *debounce_ns > 0) {
            if (now - *last_ts < *debounce_ns) return TC_ACT_OK;
        }
        bpf_map_update_elem(&last_event_ts_v4, &ip4->daddr, &now, BPF_ANY);
        send_event(&ip4->daddr, 4, now);
    } else {
        struct ipv6_lpm_key lpm_key;
        lpm_key.prefixlen = 128;
        __builtin_memcpy(&lpm_key.data, &ip6->daddr, 16);
        
        exists = bpf_map_lookup_elem(&target_ips_v6, &lpm_key);
        if (!exists) return TC_ACT_OK;

        last_ts = bpf_map_lookup_elem(&last_event_ts_v6, &ip6->daddr);
        if (last_ts && debounce_ns && *debounce_ns > 0) {
            if (now - *last_ts < *debounce_ns) return TC_ACT_OK;
        }
        bpf_map_update_elem(&last_event_ts_v6, &ip6->daddr, &now, BPF_ANY);
        send_event(&ip6->daddr, 6, now);
    }

    return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";
