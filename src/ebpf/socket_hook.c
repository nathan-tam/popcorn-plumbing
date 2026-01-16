/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * Socket Layer eBPF Hook
 * 
 * This program attaches at the socket layer, which is the closest attachment
 * point to userspace applications. Packets reach this hook after they've been
 * processed by the full network stack (including XDP, TC, netfilter, etc.).
 * 
 * Key characteristics:
 * - Latest processing point in the receive path
 * - Full skb metadata available
 * - Packets are already validated and processed by kernel
 * - Most flexible but highest latency overhead
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "common.h"

/*
 * BPF map to store per-flow packet metrics
 * 
 * This hash map tracks statistics for each unique network flow identified
 * by the 5-tuple (src_ip, dst_ip, src_port, dst_port, protocol).
 * 
 * max_entries determines how many concurrent flows we can track. Adjust
 * based on expected workload - high connection count environments may need
 * more entries.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, struct flow_key);
    __type(value, struct packet_metrics);
} socket_metrics SEC(".maps");

/*
 * Ring buffer for exporting detailed packet events to userspace
 * 
 * Currently defined but not used. This can be used to send individual
 * packet events to userspace for detailed analysis rather than just
 * aggregated statistics.
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} socket_events SEC(".maps");

/*
 * Socket filter program entry point
 * 
 * This function is called for every packet that reaches the socket layer.
 * Return value: 0 = accept packet and pass to application
 *              -1 = drop packet
 * 
 * Note: Socket filters cannot modify packets, only observe or filter them.
 */
SEC("socket_filter")
int socket_packet_filter(struct __sk_buff *skb) {
    /*
     * Get packet data boundaries
     * 
     * The eBPF verifier requires us to check all data accesses against
     * data_end to prevent out-of-bounds reads. These casts are necessary
     * for the verifier to track pointer bounds.
     */
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    
    /*
     * Parse Ethernet header
     * 
     * First, verify we have enough data for an Ethernet header.
     * The verifier requires this bounds check before accessing eth fields.
     */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return 0;  // Malformed packet, pass to application (kernel will handle it)

    /*
     * Filter for IPv4 packets only
     * 
     * eth->h_proto is in network byte order, so we use bpf_htons() to
     * convert 0x0800 (ETH_P_IP) to network byte order for comparison.
     * Non-IPv4 packets (IPv6, ARP, etc.) are passed through without processing.
     */
    if (eth->h_proto != bpf_htons(0x0800))
        return 0;

    /*
     * Parse IP header
     * 
     * Verify we have at least a minimal IP header before accessing fields.
     * Note: This doesn't account for IP options yet; that's handled in
     * extract_flow_key().
     */
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return 0;

    /*
     * Extract 5-tuple flow key
     * 
     * This helper function (defined in common.h) extracts:
     * - Source/destination IP addresses
     * - Source/destination ports (for TCP/UDP)
     * - Protocol number
     * 
     * It properly handles variable-length IP headers and performs all
     * necessary bounds checks.
     */
    struct flow_key key = {};
    if (extract_flow_key(data, data_end, &key) < 0)
        return 0;  // Failed to parse flow info (e.g., truncated packet)

    /*
     * Update packet metrics for this flow
     * 
     * We look up existing metrics for this flow. If none exist, we create
     * a new entry. If they exist, we update the counters.
     */
    struct packet_metrics *metrics = bpf_map_lookup_elem(&socket_metrics, &key);
    
    if (!metrics) {
        /*
         * First packet for this flow - create new metrics entry
         * 
         * Initialize counters with current packet's stats. The timestamp
         * is set to when we first see the flow, which can be used to
         * calculate flow duration.
         */
        struct packet_metrics new_metrics = {
            .packets_processed = 1,
            .bytes_processed = (data_end - data),
            .total_latency_ns = 0,  // Latency measurement not yet implemented
            .timestamp = bpf_ktime_get_ns(),
        };
        
        /*
         * BPF_ANY flag means: create if doesn't exist, update if exists
         * This handles race conditions where another CPU might have created
         * the entry between our lookup and update.
         */
        bpf_map_update_elem(&socket_metrics, &key, &new_metrics, BPF_ANY);
    } else {
        /*
         * Update existing flow metrics
         * 
         * Read-modify-write pattern: we read the existing metrics, update
         * the values, and write back. This is safer than in-place updates
         * and handles concurrent access better.
         * 
         * BPF_EXIST flag ensures we only update if the entry still exists
         * (though with our lock-free approach, we accept potential races).
         */
        struct packet_metrics updated = *metrics;
        updated.packets_processed++;
        updated.bytes_processed += (data_end - data);
        updated.timestamp = bpf_ktime_get_ns();  // Last seen timestamp
        
        bpf_map_update_elem(&socket_metrics, &key, &updated, BPF_EXIST);
    }

    /*
     * Accept packet and pass to application
     * 
     * Returning 0 allows the packet to continue to the socket receive
     * queue where the application can read it.
     */
    return 0;
}

/* License declaration required for eBPF programs */
char LICENSE[] SEC("license") = "Dual BSD/GPL";