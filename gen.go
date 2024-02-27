package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go track_processes bpf/src/track_processes.c -cc clang-10 bpf/src/track_processes ./bpf_src/track_processes.c -- -I/usr/include/x86_64-linux-gnu/ -O2 -target bpf
