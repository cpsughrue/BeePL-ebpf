#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct box {
  int data;
};


SEC("kprobe/sys_clone")
int bpf_shello_world(struct pt_regs *ctx) {

  struct box my_box = {.data = 42};

  bpf_printk("Hello from eBPF program! %d\n", my_box.data);
  
  return 0;
}

char _license[] SEC("license") = "GPL";

