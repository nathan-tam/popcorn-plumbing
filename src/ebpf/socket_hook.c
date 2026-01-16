/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * Socket Layer eBPF Hook
 * 
 * Attaches to a raw socket to monitor packets. Uses bpf_skb_load_bytes()
 * to read packet data since socket filters cannot use direct packet access.
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
#define ETH_HLEN    14
#define IP_HLEN_MIN 20
#define IP_HLEN_MAX 60

/* ============================================================================
 * BPF Maps
 * ============================================================================ */

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, struct flow_key);
    __type(value, struct packet_metrics);
} socket_metrics SEC(".maps");

/* ============================================================================
 * Socket Filter Program
 * ============================================================================ */

/*
 * Socket filter entry point.
 * 
 * Unlike XDP/TC, socket filters cannot directly access packet memory.
 * We must use bpf_skb_load_bytes() to copy data into local variables.
 * 
 * Return value for socket filters:
 *   0         : Drop packet  
 *   Non-zero  : Accept packet (original semantics: bytes to keep)
 */
SEC("socket")
int socket_packet_filter(struct __sk_buff *skb)
{
    /* Initialize flow key - ensure padding is zeroed for consistent lookups */
    struct flow_key key = {
        .src_ip = 0,
        .dst_ip = 0,
        .src_port = 0,
        .dst_port = 0,
        .proto = 0,
        ._pad = {0, 0, 0},
    };
    
    /* 
     * Get packet length. skb->len is accessible in socket filters.
     * Store in local variable for use throughout.
     */
    __u32 pkt_len = skb->len;
    if (pkt_len == 0)
        return 1;  /* Accept empty/unknown */
    
    /* --- Read Ethernet Header --- */
    struct ethhdr eth;
    if (bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth)) < 0)
        return pkt_len;
    
    /* Only process IPv4 */
    if (eth.h_proto != bpf_htons(ETH_P_IP))
        return pkt_len;

    /* --- Read IP Header --- */
    struct iphdr ip;
    if (bpf_skb_load_bytes(skb, ETH_HLEN, &ip, sizeof(ip)) < 0)
        return pkt_len;
    
    /* 
     * Validate IP header length.
     * IHL field is 4 bits (0-15), multiply by 4 to get bytes.
     * Valid range: 20-60 bytes.
     */
    __u32 ip_hlen = ip.ihl;
    ip_hlen *= 4;
    if (ip_hlen < IP_HLEN_MIN || ip_hlen > IP_HLEN_MAX)
        return pkt_len;

    /* Extract IP info */
    key.src_ip = ip.saddr;
    key.dst_ip = ip.daddr;
    key.proto = ip.protocol;

    /* --- Read L4 Header (TCP/UDP ports) --- */
    if (ip.protocol == IPPROTO_TCP || ip.protocol == IPPROTO_UDP) {
        /*
         * Read first 4 bytes of L4 header (src_port + dst_port).
         * Both TCP and UDP have ports at the same offset.
         * Use fixed offset for standard 20-byte IP header case,
         * with variable offset for IP options.
         */
        __u32 l4_offset = ETH_HLEN + ip_hlen;
        __u16 ports[2] = {0, 0};  /* [0]=src_port, [1]=dst_port */
        
        if (bpf_skb_load_bytes(skb, l4_offset, ports, sizeof(ports)) == 0) {
            key.src_port = ports[0];
            key.dst_port = ports[1];
        }
        /* If load fails, ports stay 0 - still track the flow by IP */
    }

    /* --- Update Flow Metrics --- */
    struct packet_metrics *metrics = bpf_map_lookup_elem(&socket_metrics, &key);
    
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
        bpf_map_update_elem(&socket_metrics, &key, &new_metrics, BPF_NOEXIST);
    }

    /* Accept packet */
    return pkt_len;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";