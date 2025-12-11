/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __PACKET_FILTER_H
#define __PACKET_FILTER_H

/* Event sent from kernel to userspace when a matching packet is detected */
struct packet_event {
    unsigned char dst_ip[16]; /* IPv4 or IPv6 address */
    unsigned int version;     /* 4 or 6 */
    unsigned int _pad;        /* padding for alignment */
    unsigned long long ts;    /* Timestamp in nanoseconds */
};

#endif
