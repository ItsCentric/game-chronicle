// go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/ptrace.h>
#include <linux/sched.h>

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __u32);
  __type(value, __u64);
  __uint(max_entries, 10240);
} process_map SEC(".maps");

// Trace open system call
SEC("kprobe/do_sys_open")
int trace_open(struct pt_regs *ctx) {
  __u32 pid = bpf_get_current_pid_tgid();
  __u64 ts = bpf_ktime_get_ns();

  // Store the timestamp in the map
  bpf_map_update_elem(&process_map, &pid, &ts, BPF_ANY);

  return 0;
}

// Trace close system call
SEC("kprobe/sys_close")
int trace_close(struct pt_regs *ctx) {
  __u32 pid = bpf_get_current_pid_tgid();
  __u64 *ts;

  // Retrieve the timestamp from the map
  ts = bpf_map_lookup_elem(&process_map, &pid);

  if (ts != NULL) {
    // Calculate the time spent between open and close
    __u64 delta = bpf_ktime_get_ns() - *ts;

    // Do something with the delta (e.g., print it)
    bpf_trace_printk("Process %d opened and closed in %llu ns\n", pid, delta);
  }

  // Remove the entry from the map
  bpf_map_delete_elem(&process_map, &pid);

  return 0;
}

char _license[] SEC("license") = "GPL";
