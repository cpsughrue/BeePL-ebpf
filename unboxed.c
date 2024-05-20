#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

int foo(int num) {
  return num;
}

SEC("kprobe/sys_clone")
int bpf_shello_world(struct pt_regs *ctx) {

    bpf_printk("Hello from eBPF program!\n");
    
    int data = foo(4);

    return 0;
}

char _license[] SEC("license") = "GPL";

