// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* eBPF program to detect packets to a specific IP and notify userspace.
 * Includes debouncing to avoid spamming events for every packet. */

#include "packet_filter.h"
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define TC_ACT_OK 0
#define ETH_P_IP 0x0800

/* Target IP to filter (index 0) and debounce interval in ns (index 1) */
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 2);
  __type(key, int);
  __type(value, __u64);
} filter_config SEC(".maps");

/* Last event timestamp for debouncing */
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, int);
  __type(value, __u64);
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
  __u64 *target_ip, *debounce_ns, *last_ts, now;

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

  /* Get target IP */
  target_ip = bpf_map_lookup_elem(&filter_config, &key);
  if (!target_ip || ip->daddr != (__u32)*target_ip)
    return TC_ACT_OK;

  /* Debounce check */
  now = bpf_ktime_get_ns();
  key = 1;
  debounce_ns = bpf_map_lookup_elem(&filter_config, &key);
  key = 0;
  last_ts = bpf_map_lookup_elem(&last_event_ts, &key);

  if (last_ts && debounce_ns && *debounce_ns > 0) {
    if (now - *last_ts < *debounce_ns)
      return TC_ACT_OK; /* Still in debounce period */
  }

  /* Update last event timestamp */
  bpf_map_update_elem(&last_event_ts, &key, &now, BPF_ANY);

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
