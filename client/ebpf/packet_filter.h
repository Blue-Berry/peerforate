/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Shared header between eBPF kernel code and OCaml userspace */
#ifndef __PACKET_FILTER_H
#define __PACKET_FILTER_H

/* Event sent from kernel to userspace when a matching packet is detected */
struct packet_event {
    unsigned int src_ip;      /* Source IP address (network byte order) */
    unsigned int dst_ip;      /* Destination IP address (network byte order) */
    unsigned short src_port;  /* Source port (network byte order) */
    unsigned short dst_port;  /* Destination port (network byte order) */
    unsigned char protocol;   /* IP protocol (TCP=6, UDP=17, ICMP=1) */
    unsigned char direction;  /* 0 = ingress, 1 = egress */
    unsigned short pkt_len;   /* Packet length */
    unsigned long long ts;    /* Timestamp in nanoseconds */
};

#endif /* __PACKET_FILTER_H */
