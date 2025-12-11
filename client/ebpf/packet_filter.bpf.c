// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* eBPF program to detect packets destined to a specific IP address
 * and notify userspace via ring buffer.
 *
 * Supports both layer 2 (Ethernet) and layer 3 (raw IP) interfaces like
 * WireGuard/tun.
 */

#include "packet_filter.h"
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define TC_ACT_OK 0
#define ETH_P_IP 0x0800

/* Configuration map - holds the target IP address to filter on */
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, int);
  __type(value, __u32); /* Target IP in network byte order */
} target_ip SEC(".maps");

/* Ring buffer for sending events to userspace */
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} events SEC(".maps");

/* Helper to parse IP header and send event */
static __always_inline int process_ip_packet(struct __sk_buff *ctx, struct iphdr *ip, void *data_end, __u32 filter_ip) {
  struct packet_event *e;

  /* Destination matches! Send event to userspace */
  e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (!e)
    return TC_ACT_OK;

  e->src_ip = ip->saddr;
  e->dst_ip = ip->daddr;
  e->protocol = ip->protocol;
  e->pkt_len = bpf_ntohs(ip->tot_len);
  e->ts = bpf_ktime_get_ns();

  /* Extract ports if TCP or UDP */
  if (ip->protocol == IPPROTO_TCP || ip->protocol == IPPROTO_UDP) {
    struct udphdr *l4 = (struct udphdr *)((void *)ip + (ip->ihl * 4));
    if ((void *)(l4 + 1) <= data_end) {
      e->src_port = l4->source;
      e->dst_port = l4->dest;
    } else {
      e->src_port = 0;
      e->dst_port = 0;
    }
  } else {
    e->src_port = 0;
    e->dst_port = 0;
  }

  bpf_ringbuf_submit(e, 0);
  return TC_ACT_OK;
}

/* TC classifier hook for egress traffic (packets being sent) */
SEC("tc")
int packet_filter_egress(struct __sk_buff *ctx) {
  void *data_end = (void *)(__u64)ctx->data_end;
  void *data = (void *)(__u64)ctx->data;
  struct iphdr *ip;
  int key = 0;
  __u32 *filter_ip;

  /* Look up the target IP we're filtering for */
  filter_ip = bpf_map_lookup_elem(&target_ip, &key);
  if (!filter_ip)
    return TC_ACT_OK;

  /* Try to detect if this is a layer 3 (raw IP) or layer 2 (Ethernet) packet.
   * For layer 3 interfaces like WireGuard/tun, data starts directly with IP
   * header. Check the IP version field (first 4 bits) to detect raw IP packets.
   */
  ip = data;
  if ((void *)(ip + 1) > data_end)
    return TC_ACT_OK;

  /* Check if first byte looks like IPv4 header (version = 4, IHL >= 5) */
  __u8 first_byte = *((__u8 *)data);
  __u8 version = first_byte >> 4;
  __u8 ihl = first_byte & 0x0F;

  if (version == 4 && ihl >= 5) {
    /* This looks like a raw IP packet (layer 3 interface like wg0) */
    /* Already pointing to IP header */
  } else if (ctx->protocol == bpf_htons(ETH_P_IP)) {
    /* This is an Ethernet frame, skip eth header */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
      return TC_ACT_OK;
    ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
      return TC_ACT_OK;
  } else {
    /* Not IPv4, skip */
    return TC_ACT_OK;
  }

  /* Verify IP header again after potential adjustment */
  if ((void *)(ip + 1) > data_end)
    return TC_ACT_OK;

  /* Check if destination matches our target IP */
  if (ip->daddr != *filter_ip)
    return TC_ACT_OK;

  return process_ip_packet(ctx, ip, data_end, *filter_ip);
}

char __license[] SEC("license") = "GPL";
