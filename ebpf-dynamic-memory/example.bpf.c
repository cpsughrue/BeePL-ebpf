#include "dynamic_memory.h"

int counter = 0;

typedef struct vec2 {
    int x;
    int y;
} vec2_t;

#ifdef native_executable 
int main() {
    printf("hello world\n");
    return 0;
}
#else
SEC("xdp")
int example(struct xdp_md *ctx) {
    (void)ctx; // supress unused variable warning
    
    vec2_t *data = (vec2_t *)static_malloc(sizeof(vec2_t));
    if (data)
        bpf_printk("valid block found");
    else
        bpf_printk("no block found");

    static_free(data);

    bpf_printk("Hello World %d", counter);
    __sync_fetch_and_add(&counter, 1);
    
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
#endif
