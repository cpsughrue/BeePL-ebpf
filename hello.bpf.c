#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

#define POOL_SIZE 1024

struct block {
    size_t size;
    bool free;
    struct block *next;
};

static uint8_t pool[POOL_SIZE];
static struct block *list = (struct block *)pool;
static bool is_initialized = false;
static uint64_t num_blocks = 1;
static struct bpf_spin_lock lock = {0};

void initialize_pool() {
    list->size = POOL_SIZE - sizeof(struct block);
    list->free = true;
    list->next = NULL;
    is_initialized = true;
}

void *static_malloc(size_t size){
    if(is_initialized == false) initialize_pool();
    
    struct block *curr = list;

    for(int i = 0; i < num_blocks; i++) {
        if(curr->free == true && curr->size >= size){
            if(curr->size <= size + sizeof(struct block)) {
                curr->free = false;
            }
            else {
                // curr is large enough to split into two blocks
                struct block *new_block = (struct block *)((uint8_t *)curr + size + sizeof(struct block));
                new_block->size = curr->size - size - sizeof(struct block);
                new_block->free = true;
                new_block->next = curr->next;

                // set values of curr
                curr->size = size;
                curr->free = false;
                curr->next = new_block;
                num_blocks++;
            }
            return (void *)((uint8_t *)curr + sizeof(struct block));
        }
        curr = curr->next;
    }
    return NULL;
}

int counter = 0;

typedef struct vec2 {
    int x;
    int y;
} vec2_t;

SEC("xdp")
int hello(struct xdp_md *ctx) {
    bpf_spin_lock(&lock);
    vec2_t *data = (vec2_t *)static_malloc(sizeof(vec2_t));
    bpf_spin_unlock(&lock);
    if(data) {
        bpf_printk("valid block found");
    } else {
        bpf_printk("invalid block found");
    } 

    bpf_printk("Hello World %d", counter);
    __sync_fetch_and_add(&counter, 1);
    
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
