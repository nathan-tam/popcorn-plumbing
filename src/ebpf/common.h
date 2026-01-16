/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * Common Definitions for eBPF Hook Points
 * 
 * Shared data structures used across XDP, TC, and socket layer hooks.
 * These structures are also used by the Python userspace program to
 * read data from BPF maps.
 */

#ifndef __COMMON_H__
#define __COMMON_H__

/* ============================================================================
 * Shared Data Structures
 * ============================================================================
 * 
 * IMPORTANT: These structures must match exactly in:
 *   - This header (used by eBPF programs)
 *   - Python controller (FlowKey and PacketMetrics classes)
 * 
 * Any changes here require corresponding changes in Python.
 */

/*
 * Flow identification key (5-tuple)
 * 
 * Uniquely identifies a network flow. Used as a key in BPF hash maps.
 * All fields are stored in network byte order as received from packets.
 * 
 * Size: 16 bytes (with padding)
 */
struct flow_key {
    __u32 src_ip;        /* Source IPv4 address (network byte order) */
    __u32 dst_ip;        /* Destination IPv4 address (network byte order) */
    __u16 src_port;      /* Source port (network byte order), 0 for non-TCP/UDP */
    __u16 dst_port;      /* Destination port (network byte order), 0 for non-TCP/UDP */
    __u8  proto;         /* IP protocol number (1=ICMP, 6=TCP, 17=UDP) */
    __u8  _pad[3];       /* Padding for 8-byte alignment */
};

/*
 * Packet metrics (per-flow statistics)
 * 
 * Tracks statistics for each flow. Stored as values in BPF hash maps.
 * 
 * Size: 32 bytes (with padding)
 * 
 * Memory layout:
 *   offset 0:  packets_processed (4 bytes)
 *   offset 4:  <padding> (4 bytes) - implicit, for 8-byte alignment
 *   offset 8:  bytes_processed (8 bytes)
 *   offset 16: total_latency_ns (8 bytes)
 *   offset 24: timestamp (8 bytes)
 */
struct packet_metrics {
    __u32 packets_processed;     /* Number of packets seen */
    __u64 bytes_processed;       /* Total bytes seen (includes all headers) */
    __u64 total_latency_ns;      /* Reserved for future latency tracking */
    __u64 timestamp;             /* Last seen time (bpf_ktime_get_ns) */
};

#endif /* __COMMON_H__ */