#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

typedef struct {
  int data;
} box_t;

SEC("kprobe/sys_clone")
int bpf_hello_world(struct pt_regs *ctx, box_t info) {
    bpf_printk("Hello from eBPF program!\n");
    return info.data;
}

char _license[] SEC("license") = "GPL";

