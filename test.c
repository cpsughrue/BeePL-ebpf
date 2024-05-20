
// Compile: clang -O1 -target bpf -c -g test.c -o test.o
// 
// -g is required to include BPF information which is needed for multiprog. If
// you don't care about multiprog then you don't need to include -g. When -g is
// included -O must not be 0 or you will run into an invalid argument error when
// trying to load the program
//
//
// Load: sudo xdp-loader load -v --mode skb --section xdp_pass enp0s31f6 test.o
// 
// skb = generic XDP mode
// native = in-driver XDP mode
// hw = offloads the program to the hardware
//
//
// Unload: sudo xdp-loader unload -v -a enp0s31f6

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

int counter = 0;

SEC("xdp")
int packet_count(void *ctx) {
    bpf_printk("%d", counter);
    counter++;
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

