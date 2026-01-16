# Project 1: Adaptive eBPF Hook Selection for Low-Latency Packet Processing

## Project Question

How does dynamic selection of eBPF attachment points (XDP, TC, socket layer) affect latency, CPU efficiency, and tail performance under changing traffic workloads?

## Project Description

This project investigates the performance trade-offs of different eBPF hook points in the Linux networking stack. Students will design and implement a system that dynamically selects where packet processing logic is attached based on runtime traffic characteristics.

The project emphasizes systems research methodology, including hypothesis formulation, controlled experimentation, and statistical analysis.

## Expected Experiments

- Implement identical packet processing logic at XDP, TC, and socket layers
- Generate diverse traffic patterns (short flows, bulk transfers, mixed workloads)
- Measure latency (mean, p95, p99), throughput, and CPU utilization
- Compare static hook placement against adaptive selection strategies

## Expected Results

- Quantitative comparison of performance across hook points
- Identification of workload regimes where dynamic hook selection is beneficial
- Analysis of trade-offs between early packet processing and flexibility

## Gained Skills

- Linux networking fundamentals
- eBPF programming (C, libbpf)
- Traffic generation and benchmarking
- Python or Go for experiment orchestration