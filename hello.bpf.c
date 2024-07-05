#if 0
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
static uint32_t num_blocks = 1;
static struct bpf_spin_lock lock = {0};

void initialize_pool() {
    list->size = POOL_SIZE - sizeof(struct block);
    list->free = true;
    list->next = NULL;
    is_initialized = true;
}

void *static_malloc(size_t size){
    if(is_initialized == false) initialize_pool();

    // must keep data 8 bytes aligned 
    if (size % 8 != 0)
        size = ((size / 8) + 1) * 8;

    if (size <= 0 || size > POOL_SIZE)
        return NULL;

    uint32_t curr_position = 0;

    for (int i = 0; i < num_blocks; i++) {
        
        if (curr_position + sizeof(struct block) > POOL_SIZE)
            return NULL;
        struct block *curr = (struct block *)(pool + curr_position);
        
        // find a block that is free and large enough to hold data
        if (curr->free == true && curr->size >= size){
            // block is either the perfect size or there is not at enogh space to split into two
            //
            // to split a block into two, curr->size must be larger then the amount of space 
            // requested by the user plus the size of a struct block
            if (curr->size <= size + sizeof(struct block)) {
                curr->free = false;
            }
            // block is large enogh to split into two
            else {
                if(curr_position + (2 * sizeof(struct block)) + size > POOL_SIZE)
                    return NULL;
                struct block *new_block = (struct block *)(pool + curr_position + sizeof(struct block) + size);

                new_block->size = curr->size - size - sizeof(struct block);
                new_block->free = true;
                new_block->next = curr->next;

                // set values of curr
                curr->size = size;
                curr->free = false;
                curr->next = new_block;
                num_blocks++;
            }
            
            if (curr_position + sizeof(struct block) + size > POOL_SIZE)
                return NULL;
            return &pool[curr_position + sizeof(struct block)];
        }
        curr_position += sizeof(struct block) + curr->size;
    }
    return NULL;
}


#else

#include <stdint.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// Maximim number of allocations. 
// 
// Same number of allocations as would be possible with the linked list 
// approach. struct block is 24 bytes plus a minimum of 8 bytes of data per 
// allocation (8 byte minimum due to 8 byte alignment) results in a minimum 
// allocation of 32 bytes and 1024 / 32 = 32
#define MAX_ALLOCS 32
#define POOL_SIZE 1024

struct alloc_info {
    uint32_t start;
    uint32_t size;
};

// zero initialized: https://docs.kernel.org/bpf/map_array.html
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, uint32_t);
    __type(value, uint8_t[POOL_SIZE]);
} memory_pool SEC(".maps");

// zero initialized: https://docs.kernel.org/bpf/map_array.html
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, uint32_t);
    __type(value, struct alloc_info[MAX_ALLOCS]);
} alloc_metadata SEC(".maps");

static __always_inline void *static_malloc(uint32_t size) {
    if (size == 0 || size > POOL_SIZE)
        return NULL;

    // must keep data 8 bytes aligned 
    if (size % 8 != 0)
        size = ((size / 8) + 1) * 8;

    uint32_t key = 0;
    uint8_t *pool = bpf_map_lookup_elem(&memory_pool, &key);
    struct alloc_info *metadata = bpf_map_lookup_elem(&alloc_metadata, &key);
    if (!pool || !metadata)
        return NULL;

    uint32_t current_pos = 0;
    uint32_t alloc_index = -1;

    // because alloc_metadata is zero initalized, if alloc_info::size is 0 then
    // that index can be used to store meta data
    for (int i = 0; i < MAX_ALLOCS; i++) {
        if (metadata[i].size == 0) {
            alloc_index = i;
            break;
        }
        current_pos += metadata[i].size;
    }

    if (alloc_index == -1)
        return NULL; 

    // check to make sure there is enough space
    if (current_pos + size > POOL_SIZE)
        return NULL;

    metadata[alloc_index].start = current_pos;
    metadata[alloc_index].size = size;

    return &pool[current_pos];
}

// ptr will still be valid after calling static_free
static __always_inline void static_free(void *ptr) {
    uint32_t key = 0;
    uint8_t *pool = bpf_map_lookup_elem(&memory_pool, &key);
    struct alloc_info *metadata = bpf_map_lookup_elem(&alloc_metadata, &key);
    if (!pool || !metadata || !ptr)
        return;

    uint32_t ptr_offset = (uint8_t *)ptr - pool;
    for (int i = 0; i < MAX_ALLOCS; i++) {
        // find the metadata block that corresponds with the pointer being freed
        if (metadata[i].start == ptr_offset) {
            
            // calculate the number of bytes that have been allocated to the 
            // right of ptr in memory_pool
            uint32_t size_to_move = 0;
            for (int j = i + 1; j < MAX_ALLOCS; j++) {
                size_to_move += metadata[j].size;
            }

            if (size_to_move > 0) {
                // Shift data to the left. (dst, source, size)
                if (metadata[i].start + metadata[i].size + size_to_move > POOL_SIZE && 
                    metadata[i].start <= 0 && 
                    metadata[i].start + metadata[i].size <= 0)
                return;

                bpf_probe_read_kernel(&pool[metadata[i].start], 
                                      size_to_move, 
                                      &pool[metadata[i].start + metadata[i].size]);
    



    //             if(result < 0)
    //                 return;

    //             // Shift all alloc_metadata entries left one 
    //             uint32_t size_removed = metadata[i].size;
    //             for (int j = i + 1; j < MAX_ALLOCS; j++) {
    //                 metadata[j - 1] = metadata[j];
    //                 if(metadata[j].size != 0)
    //                     metadata[j - 1].start -= size_removed;
    //             }
            }

    //         // Clear the last alloc_metadata entry
    //         metadata[MAX_ALLOCS - 1].start = 0;
    //         metadata[MAX_ALLOCS - 1].size = 0;
    //         break;
        }
    }
}
#endif

int counter = 0;

typedef struct vec2 {
    int x;
    int y;
} vec2_t;

SEC("xdp")
int hello(struct xdp_md *ctx) {
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
