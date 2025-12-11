/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __PACKET_FILTER_H
#define __PACKET_FILTER_H

/* Minimal event - just destination IP and timestamp */
struct packet_event {
    unsigned int dst_ip;
    unsigned long long ts;
};

#endif
