/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * TC (Traffic Control) Layer eBPF Hook - CORRECTED
 * * Attaches to the TC ingress/egress hook point to monitor packets.
 * Now supports VLANs and properly parses Ethernet headers.
 */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "common.h" // <-- use shared structs (flow_key, packet_metrics) expected by userspace

// EtherTypes (avoid relying on toolchain/kernel header availability)
#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif
#ifndef ETH_P_8021Q
#define ETH_P_8021Q 0x8100
#endif
#ifndef ETH_P_8021AD
#define ETH_P_8021AD 0x88A8
#endif

// Some toolchains won't expose these via vmlinux.h alone.
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

// IPv4 fragmentation bits (in frag_off, network order on the wire; use bpf_ntohs before masking)
#ifndef IP_MF
#define IP_MF 0x2000
#endif
#ifndef IP_OFFSET
#define IP_OFFSET 0x1FFF
#endif

// Packet parsing limits
#define MAX_VLAN_DEPTH 2

#define TC_ACT_OK    0

/* ============================================================================
 * BPF Maps
 * ============================================================================ */

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, struct flow_key);
    __type(value, struct packet_metrics);
} tc_metrics SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u64);
} tc_debug SEC(".maps");

// Debug Indicies
enum {
    DBG_TOTAL_PACKETS = 0,
    DBG_NOT_IP,
    DBG_IPV4_PACKETS,
    DBG_PARSED_PACKETS,
    DBG_MAP_UPDATES,
    DBG_MAP_NOEXIST,
    DBG_ERR_BOUNDS,
    DBG_ERR_HEADER
};

static __always_inline void debug_inc(__u32 idx)
{
    __u64 *counter = bpf_map_lookup_elem(&tc_debug, &idx);
    if (counter)
        __sync_fetch_and_add(counter, 1);
}

/* ============================================================================
 * Packet Processing
 * ============================================================================ */

SEC("tc")
int tc_packet_filter(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    __u8 *data8 = data;

    debug_inc(DBG_TOTAL_PACKETS);

    // 1. PARSE ETHERNET HEADER
    struct ethhdr *eth = (struct ethhdr *)data8;
    if ((void *)(eth + 1) > data_end) {
        debug_inc(DBG_ERR_BOUNDS);
        return TC_ACT_OK;
    }

    __u16 h_proto = eth->h_proto;
    int l3_offset = sizeof(struct ethhdr);

    // 2. HANDLE VLANs (Loop unrolled for Verifier)
    // We iterate to unwrap VLAN tags (802.1Q / 802.1AD) to find the real L3 protocol
    #pragma unroll
    for (int i = 0; i < MAX_VLAN_DEPTH; i++) {
        if (h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD)) {
            struct vlan_hdr *vhdr = (struct vlan_hdr *)(data8 + l3_offset);
            if ((void *)(vhdr + 1) > data_end) {
                debug_inc(DBG_ERR_BOUNDS);
                return TC_ACT_OK;
            }
            h_proto = vhdr->h_vlan_encapsulated_proto;
            l3_offset += sizeof(struct vlan_hdr);
        } else {
            break; // Not a VLAN, stop looking
        }
    }

    // 3. CHECK IF IT IS IPv4
    if (h_proto != bpf_htons(ETH_P_IP)) {
        debug_inc(DBG_NOT_IP);
        return TC_ACT_OK;
    }

    debug_inc(DBG_IPV4_PACKETS);

    // 4. PARSE IP HEADER
    struct iphdr *ip = (struct iphdr *)(data8 + l3_offset);
    if ((void *)(ip + 1) > data_end) {
        debug_inc(DBG_ERR_BOUNDS);
        return TC_ACT_OK;
    }

    // Verify IPv4
    if (ip->version != 4) {
        debug_inc(DBG_ERR_HEADER);
        return TC_ACT_OK;
    }

    // Calculate dynamic IP header length (IHL * 4)
    __u32 ip_hlen = ip->ihl * 4;
    if (ip_hlen < 20 || ip_hlen > 60) {
        debug_inc(DBG_ERR_HEADER);
        return TC_ACT_OK;
    }

    // Ensure variable length IP header is within bounds
    if ((void *)((__u8 *)ip + ip_hlen) > data_end) {
        debug_inc(DBG_ERR_BOUNDS);
        return TC_ACT_OK;
    }

    // Skip all IPv4 fragments (non-first fragments don't carry L4 headers reliably).
    __u16 frag = bpf_ntohs(ip->frag_off);
    if (frag & (IP_MF | IP_OFFSET)) {
        debug_inc(DBG_ERR_HEADER);
        return TC_ACT_OK;
    }

    // 5. INITIALIZE FLOW KEY
    // IMPORTANT: `struct flow_key` is shared with userspace via `common.h`.
    // Keep the padding zeroed so map lookups are deterministic.
    struct flow_key flow = {
        .src_ip = 0,
        .dst_ip = 0,
        .src_port = 0,
        .dst_port = 0,
        .proto = 0,
        ._pad = {0, 0, 0},
    };

    flow.src_ip = ip->saddr;
    flow.dst_ip = ip->daddr;
    flow.proto = ip->protocol;

    // 6. PARSE L4 (TCP/UDP)
    __u8 *l4 = (__u8 *)ip + ip_hlen;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)l4;
        if ((void *)(tcp + 1) <= data_end) {
            flow.src_port = tcp->source;
            flow.dst_port = tcp->dest;
        }
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr *)l4;
        if ((void *)(udp + 1) <= data_end) {
            flow.src_port = udp->source;
            flow.dst_port = udp->dest;
        }
    }

    debug_inc(DBG_PARSED_PACKETS);

    // 7. UPDATE METRICS
    __u32 pkt_len = skb->len;
    __u64 now = bpf_ktime_get_ns();
    struct packet_metrics *metrics = bpf_map_lookup_elem(&tc_metrics, &flow);

    if (metrics) {
        __sync_fetch_and_add(&metrics->packets_processed, 1);
        __sync_fetch_and_add(&metrics->bytes_processed, pkt_len);

        // Accumulate inter-arrival time as a simple per-flow latency proxy.
        __u64 last = metrics->timestamp;
        if (last)
            __sync_fetch_and_add(&metrics->total_latency_ns, now - last);

        metrics->timestamp = now;
        debug_inc(DBG_MAP_UPDATES);
    } else {
        struct packet_metrics new_metrics = {
            .packets_processed = 1,
            .bytes_processed = pkt_len,
            .total_latency_ns = 0,
            .timestamp = now,
        };

        if (bpf_map_update_elem(&tc_metrics, &flow, &new_metrics, BPF_NOEXIST) == 0) {
            debug_inc(DBG_MAP_UPDATES);
        } else {
            // Likely race: key inserted after our lookup. Re-lookup and update.
            debug_inc(DBG_MAP_NOEXIST);

            metrics = bpf_map_lookup_elem(&tc_metrics, &flow);
            if (metrics) {
                __sync_fetch_and_add(&metrics->packets_processed, 1);
                __sync_fetch_and_add(&metrics->bytes_processed, pkt_len);

                __u64 last = metrics->timestamp;
                if (last)
                    __sync_fetch_and_add(&metrics->total_latency_ns, now - last);

                metrics->timestamp = now;
                debug_inc(DBG_MAP_UPDATES);
            }
        }
    }

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";