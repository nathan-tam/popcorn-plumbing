/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * TC (Traffic Control) Layer eBPF Hook
 * 
 * Attaches to the TC ingress/egress hook point to monitor packets.
 * Unlike socket filters, TC programs can use direct packet access
 * (data/data_end pointers) for more efficient packet parsing.
 * 
 * Attachment:
 *   tc qdisc add dev <iface> clsact
 *   tc filter add dev <iface> ingress bpf direct-action obj tc_hook.o sec tc_ingress
 *   tc filter add dev <iface> egress bpf direct-action obj tc_hook.o sec tc_egress
 */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "common.h"

/* Protocol numbers */
#define ETH_P_IP    0x0800
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

/* Header sizes */
#define IP_HLEN_MIN 20
#define IP_HLEN_MAX 60

/* TC return values */
#define TC_ACT_OK       0   /* Continue processing */
#define TC_ACT_SHOT     2   /* Drop packet */

/* ============================================================================
 * BPF Maps
 * ============================================================================ */

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, struct flow_key);
    __type(value, struct packet_metrics);
} tc_metrics SEC(".maps");

/* ============================================================================
 * Packet Processing Helper
 * ============================================================================ */

/*
 * Parse packet and update flow metrics.
 * 
 * This helper is shared between ingress and egress hooks to avoid
 * code duplication. Must be static inline for eBPF.
 * 
 * Returns: TC_ACT_OK (always continues processing)
 */
static __always_inline int process_packet(struct __sk_buff *skb)
{
    /* Get packet boundaries for direct access */
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    
    /* Get packet length early */
    __u32 pkt_len = skb->len;
    if (pkt_len == 0)
        return TC_ACT_OK;

    /* --- Parse Ethernet Header --- */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;
    
    /* Only process IPv4 */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    /* --- Parse IP Header --- */
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;
    
    /* 
     * Validate IP header length.
     * IHL field is 4 bits (0-15), multiply by 4 to get bytes.
     * Valid range: 20-60 bytes.
     */
    __u32 ip_hlen = ip->ihl * 4;
    if (ip_hlen < IP_HLEN_MIN || ip_hlen > IP_HLEN_MAX)
        return TC_ACT_OK;

    /* Verify we can access the full IP header (including options) */
    if ((__u8 *)ip + ip_hlen > (__u8 *)data_end)
        return TC_ACT_OK;

    /* Initialize flow key - ensure padding is zeroed for consistent lookups */
    struct flow_key key = {
        .src_ip = ip->saddr,
        .dst_ip = ip->daddr,
        .src_port = 0,
        .dst_port = 0,
        .proto = ip->protocol,
        ._pad = {0, 0, 0},
    };

    /* --- Parse L4 Header (TCP/UDP ports) --- */
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)((__u8 *)ip + ip_hlen);
        if ((void *)(tcp + 1) <= data_end) {
            key.src_port = tcp->source;
            key.dst_port = tcp->dest;
        }
        /* If bounds check fails, ports stay 0 - still track flow by IP */
    } 
    else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr *)((__u8 *)ip + ip_hlen);
        if ((void *)(udp + 1) <= data_end) {
            key.src_port = udp->source;
            key.dst_port = udp->dest;
        }
    }

    /* --- Update Flow Metrics --- */
    struct packet_metrics *metrics = bpf_map_lookup_elem(&tc_metrics, &key);
    
    if (metrics) {
        /* Update existing entry atomically */
        __sync_fetch_and_add(&metrics->packets_processed, 1);
        __sync_fetch_and_add(&metrics->bytes_processed, pkt_len);
        metrics->timestamp = bpf_ktime_get_ns();
    } else {
        /* Create new entry */
        struct packet_metrics new_metrics = {
            .packets_processed = 1,
            .bytes_processed = pkt_len,
            .total_latency_ns = 0,
            .timestamp = bpf_ktime_get_ns(),
        };
        bpf_map_update_elem(&tc_metrics, &key, &new_metrics, BPF_NOEXIST);
    }

    return TC_ACT_OK;
}

/* ============================================================================
 * TC Classifier Programs
 * ============================================================================ */

/*
 * TC ingress classifier entry point.
 * 
 * Processes incoming packets before they reach the network stack.
 * Attach with: tc filter add dev <iface> ingress bpf direct-action obj tc_hook.o sec tc_ingress
 */
SEC("tc_ingress")
int tc_ingress_filter(struct __sk_buff *skb)
{
    return process_packet(skb);
}

/*
 * TC egress classifier entry point.
 * 
 * Processes outgoing packets before they leave the interface.
 * Attach with: tc filter add dev <iface> egress bpf direct-action obj tc_hook.o sec tc_egress
 */
SEC("tc_egress")
int tc_egress_filter(struct __sk_buff *skb)
{
    return process_packet(skb);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";