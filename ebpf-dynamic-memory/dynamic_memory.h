#ifndef DYNAMIC_MEMORY_H
#define DYNAMIC_MEMORY_H

#include <stdint.h>
#include <stdbool.h>
#ifdef native_executable 
#include <stdio.h>
#else
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#endif

// Maximum number of allocations. 
// 
// Same number of allocations as would be possible with the linked list 
// approach. struct block is 24 bytes plus a minimum of 8 bytes of data per 
// allocation (8 byte minimum due to 8 byte alignment) results in a minimum 
// allocation of 32 bytes and 1024 / 32 = 32
#ifndef MAX_ALLOCS
#define MAX_ALLOCS 32
#endif

#ifndef POOL_SIZE
#define POOL_SIZE 1024
#endif

#ifdef native_executable
// wrap memory_pool in a struct to provide the same interface as the eBPF map
struct pool_map_t { uint8_t memory_pool[POOL_SIZE];} pool_map = {{0}};
#else
// zero initialized: https://docs.kernel.org/bpf/map_array.html
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, uint32_t);
    __type(value, uint8_t[POOL_SIZE]);
} pool_map SEC(".maps");
#endif

struct malloc {
    bool     in_use;
    uint32_t start;
    uint32_t size;
};

struct malloc_metadata {
    struct malloc data[MAX_ALLOCS];
#ifdef native_executable
    int lock;
#else
    struct bpf_spin_lock lock;
#endif
};

#ifdef native_executable
struct malloc_metadata metadata_map = {0};
// create stub to reduce number of #ifdef in static_malloc and static_free
void bpf_spin_lock(int *lock){(void)lock;};
void bpf_spin_unlock(int *lock){(void)lock;};
#else
// zero initialized: https://docs.kernel.org/bpf/map_array.html
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, uint32_t);
    __type(value, struct malloc_metadata);
} metadata_map SEC(".maps");
#endif

static __always_inline uint8_t *get_pool(void *pool_map) {
#ifdef native_executable
    return ((struct pool_map_t*)pool_map)->memory_pool;
#else
    uint32_t key = 0;
    return bpf_map_lookup_elem(pool_map, &key);
#endif
}

static __always_inline struct malloc_metadata *get_metadata(void *metadata_map) {
#ifdef native_executable
    return metadata_map;
#else
    uint32_t key = 0;
    return bpf_map_lookup_elem(metadata_map, &key);
#endif
}

static __always_inline void *static_malloc(uint32_t size) {
    if (size == 0 || size > POOL_SIZE)
        return NULL;

    // must keep data 8 bytes aligned 
    if (size % 8 != 0)
        size = ((size / 8) + 1) * 8;

    uint8_t *pool = get_pool(&pool_map);
    struct malloc_metadata *metadata = get_metadata(&metadata_map);
    if (!pool || !metadata)
        return NULL;

    // Use 64 bit values to provide flexibility in setting POOL_SIZE and MAX_ALLOCS
    uint64_t current_pos = 0; // [0, POOL_SIZE]
    int64_t alloc_index = -1; // [-1, MAX_ALLOCS]

    bpf_spin_lock(&metadata->lock);

    // because alloc_metadata is zero initalized, if alloc_info::size is 0 then
    // that index can be used to store meta data
    for (int i = 0; i < MAX_ALLOCS; i++) {
        if ((metadata->data[i].size == 0 || metadata->data[i].size >= size) && !metadata->data[i].in_use) {
            alloc_index = i;
            break;
        }
        current_pos += metadata->data[i].size;
    }

    if (alloc_index == -1) {
        bpf_spin_unlock(&metadata->lock);
        return NULL;
    }

    // check to make sure there is enough space
    if (current_pos + size > POOL_SIZE) {
        bpf_spin_unlock(&metadata->lock);
        return NULL;
    }

    metadata->data[alloc_index].in_use = true;
    metadata->data[alloc_index].start = current_pos;
    metadata->data[alloc_index].size = size;

    bpf_spin_unlock(&metadata->lock);
    return &pool[current_pos];
}

// ptr will still be valid after calling static_free
static __always_inline void static_free(void *ptr) {
    if(!ptr)
        return;

    uint8_t *pool = get_pool(&pool_map);
    struct malloc_metadata *metadata = get_metadata(&metadata_map);
    if (!pool || !metadata)
        return;

    uint32_t ptr_offset = (uint8_t *)ptr - pool;
    for (int i = 0; i < MAX_ALLOCS; i++) {
        // find the metadata block that corresponds with the pointer being freed
        if (metadata->data[i].start == ptr_offset) {
            metadata->data[i].in_use = false;
            return;
        }
    }
}

#endif // DYNAMIC_MEMORY_H
