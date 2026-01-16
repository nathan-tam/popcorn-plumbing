/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * Common Definitions and Helpers for eBPF Hook Points
 * 
 * This header contains shared data structures and helper functions used
 * across all three eBPF attachment points (XDP, TC, and socket layer).
 * 
 * The goal is to ensure identical packet processing logic at each hook
 * point for fair performance comparison.
 */

#ifndef __COMMON_H__
#define __COMMON_H__

#include <bpf/bpf_endian.h>

/*
 * Packet metrics structure
 * 
 * This structure tracks statistics for each network flow. It's stored in
 * BPF hash maps and updated as packets are processed.
 * 
 * Fields:
 * - packets_processed: Total number of packets seen for this flow
 * - bytes_processed: Total bytes (including all headers) seen for this flow
 * - total_latency_ns: Cumulative processing latency in nanoseconds (reserved)
 * - timestamp: Last time this flow was seen (nanoseconds since boot)
 * 
 * Note: All fields use naturally aligned types to avoid padding issues
 * when sharing data between kernel and userspace.
 */
struct packet_metrics {
    __u32 packets_processed;     /* Packet counter */
    __u64 bytes_processed;       /* Byte counter */
    __u64 total_latency_ns;      /* Reserved for latency measurement */
    __u64 timestamp;             /* Last seen timestamp (from bpf_ktime_get_ns) */
};

/*
 * Flow identification key (5-tuple)
 * 
 * This structure uniquely identifies a network flow using the standard
 * 5-tuple: source IP, destination IP, source port, destination port, and
 * protocol number.
 * 
 * Used as a key in BPF hash maps to track per-flow statistics.
 * 
 * Fields are in host byte order (network byte order is converted during
 * parsing for consistency and easier debugging).
 * 
 * Padding: _pad[3] ensures the structure is 8-byte aligned and has
 * consistent size across architectures.
 */
struct flow_key {
    __u32 src_ip;        /* Source IPv4 address */
    __u32 dst_ip;        /* Destination IPv4 address */
    __u16 src_port;      /* Source port (TCP/UDP) or 0 for other protocols */
    __u16 dst_port;      /* Destination port (TCP/UDP) or 0 for other protocols */
    __u8  proto;         /* IP protocol number (6=TCP, 17=UDP, etc.) */
    __u8  _pad[3];       /* Explicit padding for alignment */
};

/*
 * Extract flow key from packet data
 * 
 * This helper function parses packet headers and extracts the 5-tuple flow
 * identifier. It performs all necessary bounds checking required by the
 * eBPF verifier.
 * 
 * Parameters:
 * - data: Pointer to start of packet data
 * - data_end: Pointer to end of packet data (for bounds checking)
 * - key: Output parameter - populated with flow information on success
 * 
 * Return value:
 * - 0 on success
 * - -1 on failure (malformed packet, non-IPv4, truncated headers, etc.)
 * 
 * The function handles:
 * - Variable-length IP headers (accounts for IP options via ihl field)
 * - TCP and UDP port extraction
 * - Proper bounds checking at each parsing step
 * - Non-TCP/UDP protocols (ports set to 0)
 * 
 * __always_inline ensures this is inlined at each call site, which is
 * critical for eBPF programs to pass the verifier's complexity limits.
 */
static __always_inline int extract_flow_key(void *data, void *data_end, 
                                            struct flow_key *key) {
    /*
     * Parse Ethernet header
     * 
     * We need at least 14 bytes for an Ethernet header. The verifier
     * requires this bounds check before we can access any eth fields.
     */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;

    /*
     * Filter for IPv4 only
     * 
     * eth->h_proto is in network byte order. ETH_P_IP (0x0800) represents
     * IPv4. We use bpf_htons() to convert our constant to network byte order.
     * 
     * Non-IPv4 packets (IPv6, ARP, VLAN-tagged, etc.) are rejected here.
     */
    if (eth->h_proto != bpf_htons(0x0800))
        return -1;

    /*
     * Parse IP header (minimum size check)
     * 
     * First verify we have at least 20 bytes (minimum IP header size).
     * We'll adjust for IP options below.
     */
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return -1;

    /*
     * Validate IP header length (IHL field)
     * 
     * The IHL (Internet Header Length) field specifies the header length
     * in 32-bit words. Valid range is 5-15 (20-60 bytes).
     * 
     * ihl < 5 indicates a malformed packet (header too short)
     * We check this before using ihl in calculations to prevent issues.
     */
    if (ip->ihl < 5)
        return -1;

    /*
     * Extract IP addresses and protocol
     * 
     * These fields are at fixed positions in the IP header, so we can
     * safely access them after our bounds checks above.
     * 
     * Note: IP addresses are stored in network byte order in the packet,
     * and we keep them that way in our flow_key for consistency.
     */
    key->src_ip = ip->saddr;
    key->dst_ip = ip->daddr;
    key->proto = ip->protocol;

    /*
     * Calculate Layer 4 (TCP/UDP) header position
     * 
     * IP headers can have options, so we can't assume the L4 header starts
     * immediately after the minimum IP header. We use the IHL field to
     * calculate the actual header length:
     * 
     * IP header length in bytes = ihl * 4
     * 
     * This correctly handles both:
     * - Standard 20-byte IP headers (ihl = 5)
     * - IP headers with options (ihl > 5)
     */
    void *l4_hdr = (void *)ip + (ip->ihl * 4);

    /*
     * Verify L4 header is within packet bounds
     * 
     * Before accessing TCP/UDP headers, ensure the L4 header position
     * is actually within the packet. This prevents reading beyond packet
     * boundaries if IP options are malformed or the packet is truncated.
     */
    if (l4_hdr > data_end)
        return -1;

    /*
     * Extract port numbers based on protocol
     * 
     * TCP (protocol 6) and UDP (protocol 17) both have source/dest ports
     * at the same offset (first 4 bytes of L4 header).
     * 
     * For other protocols (ICMP, etc.), we set ports to 0 since they
     * don't have port numbers.
     */
    if (ip->protocol == 6) {  /* IPPROTO_TCP = 6 */
        struct tcphdr *tcp = l4_hdr;
        
        /*
         * Verify we have at least the TCP header up to the port fields.
         * We only need the first 4 bytes (source + dest ports), but checking
         * the full header is safer and matches UDP handling.
         */
        if ((void *)(tcp + 1) > data_end)
            return -1;
        
        /*
         * TCP ports are in network byte order in the packet.
         * We keep them in network byte order in our flow_key.
         */
        key->src_port = tcp->source;
        key->dst_port = tcp->dest;
        
    } else if (ip->protocol == 17) {  /* IPPROTO_UDP = 17 */
        struct udphdr *udp = l4_hdr;
        
        /*
         * Verify we have at least the UDP header (8 bytes).
         * Like TCP, we only need the first 4 bytes for ports.
         */
        if ((void *)(udp + 1) > data_end)
            return -1;
        
        /*
         * UDP ports are in network byte order in the packet.
         * We keep them in network byte order in our flow_key.
         */
        key->src_port = udp->source;
        key->dst_port = udp->dest;
        
    } else {
        /*
         * Non-TCP/UDP protocols (ICMP, IGMP, ESP, etc.)
         * 
         * These protocols don't have port numbers, so we set both to 0.
         * The flow will be identified solely by IP addresses and protocol.
         */
        key->src_port = 0;
        key->dst_port = 0;
    }

    /* Successfully extracted flow information */
    return 0;
}

#endif /* __COMMON_H__ */