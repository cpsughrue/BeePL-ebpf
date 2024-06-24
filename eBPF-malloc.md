# Emulating `malloc` and `free` in eBPF


The goal of this experiment is to take the program bellow and replace `malloc` with a custom allocator `static_malloc` such that it will be accepted by the eBPF verifier. Idealy `static_malloc` should emulate `malloc` such that any invalid eBPF program can be made valid by replacing all instance of `malloc` with `static_malloc` and including a single headerfile.

```c
// hello.bpf.c

typedef struct vec2 {
    uint8_t x;
    uint8_t y;
} vec2_t;

int counter = 0;

SEC("xdp")
int hello(struct xdp_md *ctx) {

    vec2_t *data = (vec2_t *)malloc(sizeof(vec2_t));

    bpf_printk("Hello World %d", counter);
    counter++; 
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
```


### Linked list allocator

First instinct is to implement a linked list allocator that uses memory from a large static array of `uint8_t`.


<details>
  <summary>Beginning of simple implementation</summary>

```c
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
static struct block *free_list = (struct block *)pool;
static bool is_initialized = false;
static struct bpf_spin_lock lock = {0}; 

void initialize_pool() {
    free_list->size = POOL_SIZE - sizeof(struct block);
    free_list->free = true;
    free_list->next = NULL;
    is_initialized = true;
}

void *static_malloc(size_t size){
    bpf_spin_lock(&lock);
    if(is_initialized == false) initialize_pool();
    bpf_spin_unlock(&lock);
    
    free_list->free = false;
    return (void *)((uint8_t *)free_list + sizeof(struct block));
}

int counter = 0;

typedef struct vec2 {
    int x;
    int y;
} vec2_t;

SEC("xdp")
int hello(struct xdp_md *ctx) {
    vec2_t *data = (vec2_t *)static_malloc(sizeof(vec2_t));    
    data->x = counter;

    bpf_printk("Hello World %d at %d", data->x, data);
    __sync_fetch_and_add(&counter, 1);
    
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
```
</details>

* Compile with `clang -target bpf -g -O2 -o hello.bpf.o -c hello.bpf.c`. 
* Dump object file with `llvm-objdump -S hello.bpf.o`

<details>
  <summary>object file</summary>

```
hello.bpf.o:    file format elf64-bpf

Disassembly of section .text:

0000000000000000 <initialize_pool>:
;     free_list->size = POOL_SIZE - sizeof(struct block);
       0:       18 01 00 00 10 00 00 00 00 00 00 00 00 00 00 00 r1 = 0x10 ll
       2:       b7 02 00 00 00 00 00 00 r2 = 0x0
;     free_list->next = NULL;
       3:       7b 21 10 00 00 00 00 00 *(u64 *)(r1 + 0x10) = r2
       4:       b7 02 00 00 e8 03 00 00 r2 = 0x3e8
;     free_list->size = POOL_SIZE - sizeof(struct block);
       5:       7b 21 00 00 00 00 00 00 *(u64 *)(r1 + 0x0) = r2
       6:       b7 02 00 00 01 00 00 00 r2 = 0x1
;     free_list->free = true;
       7:       73 21 08 00 00 00 00 00 *(u8 *)(r1 + 0x8) = r2
;     is_initialized = true;
       8:       18 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 r1 = 0x0 ll
      10:       73 21 00 00 00 00 00 00 *(u8 *)(r1 + 0x0) = r2
; }
      11:       95 00 00 00 00 00 00 00 exit

0000000000000060 <static_malloc>:
;     bpf_spin_lock(&lock);
      12:       18 01 00 00 04 00 00 00 00 00 00 00 00 00 00 00 r1 = 0x4 ll
      14:       85 00 00 00 5d 00 00 00 call 0x5d
;     if(is_initialized == false) initialize_pool();
      15:       18 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 r1 = 0x0 ll
      17:       71 12 00 00 00 00 00 00 r2 = *(u8 *)(r1 + 0x0)
      18:       55 02 09 00 00 00 00 00 if r2 != 0x0 goto +0x9 <LBB1_2>
;     free_list->size = POOL_SIZE - sizeof(struct block);
      19:       18 02 00 00 10 00 00 00 00 00 00 00 00 00 00 00 r2 = 0x10 ll
      21:       b7 03 00 00 00 00 00 00 r3 = 0x0
;     free_list->next = NULL;
      22:       7b 32 10 00 00 00 00 00 *(u64 *)(r2 + 0x10) = r3
      23:       b7 03 00 00 e8 03 00 00 r3 = 0x3e8
;     free_list->size = POOL_SIZE - sizeof(struct block);
      24:       7b 32 00 00 00 00 00 00 *(u64 *)(r2 + 0x0) = r3
      25:       b7 03 00 00 01 00 00 00 r3 = 0x1
;     free_list->free = true;
      26:       73 32 08 00 00 00 00 00 *(u8 *)(r2 + 0x8) = r3
;     is_initialized = true;
      27:       73 31 00 00 00 00 00 00 *(u8 *)(r1 + 0x0) = r3

00000000000000e0 <LBB1_2>:
;     bpf_spin_unlock(&lock);
      28:       18 01 00 00 04 00 00 00 00 00 00 00 00 00 00 00 r1 = 0x4 ll
      30:       85 00 00 00 5e 00 00 00 call 0x5e
;     free_list->free = false;
      31:       18 00 00 00 10 00 00 00 00 00 00 00 00 00 00 00 r0 = 0x10 ll
      33:       b7 01 00 00 00 00 00 00 r1 = 0x0
      34:       73 10 08 00 00 00 00 00 *(u8 *)(r0 + 0x8) = r1
;     return (void *)((uint8_t *)free_list + sizeof(struct block));
      35:       07 00 00 00 18 00 00 00 r0 += 0x18
      36:       95 00 00 00 00 00 00 00 exit

Disassembly of section xdp:

0000000000000000 <hello>:
;     bpf_spin_lock(&lock);
       0:       18 01 00 00 04 00 00 00 00 00 00 00 00 00 00 00 r1 = 0x4 ll
       2:       85 00 00 00 5d 00 00 00 call 0x5d
;     if(is_initialized == false) initialize_pool();
       3:       18 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 r1 = 0x0 ll
       5:       71 12 00 00 00 00 00 00 r2 = *(u8 *)(r1 + 0x0)
       6:       55 02 09 00 00 00 00 00 if r2 != 0x0 goto +0x9 <LBB2_2>
;     free_list->size = POOL_SIZE - sizeof(struct block);
       7:       18 02 00 00 10 00 00 00 00 00 00 00 00 00 00 00 r2 = 0x10 ll
       9:       b7 03 00 00 00 00 00 00 r3 = 0x0
;     free_list->next = NULL;
      10:       7b 32 10 00 00 00 00 00 *(u64 *)(r2 + 0x10) = r3
      11:       b7 03 00 00 e8 03 00 00 r3 = 0x3e8
;     free_list->size = POOL_SIZE - sizeof(struct block);
      12:       7b 32 00 00 00 00 00 00 *(u64 *)(r2 + 0x0) = r3
      13:       b7 03 00 00 01 00 00 00 r3 = 0x1
;     free_list->free = true;
      14:       73 32 08 00 00 00 00 00 *(u8 *)(r2 + 0x8) = r3
;     is_initialized = true;
      15:       73 31 00 00 00 00 00 00 *(u8 *)(r1 + 0x0) = r3

0000000000000080 <LBB2_2>:
;     bpf_spin_unlock(&lock);
      16:       18 01 00 00 04 00 00 00 00 00 00 00 00 00 00 00 r1 = 0x4 ll
      18:       85 00 00 00 5e 00 00 00 call 0x5e
;     free_list->free = false;
      19:       18 04 00 00 10 00 00 00 00 00 00 00 00 00 00 00 r4 = 0x10 ll
      21:       b7 01 00 00 00 00 00 00 r1 = 0x0
      22:       73 14 08 00 00 00 00 00 *(u8 *)(r4 + 0x8) = r1
;     data->x = counter;
      23:       18 06 00 00 00 00 00 00 00 00 00 00 00 00 00 00 r6 = 0x0 ll
;     bpf_printk("Hello World %d at %d", data->x, data);
      25:       61 63 00 00 00 00 00 00 r3 = *(u32 *)(r6 + 0x0)
;     data->x = counter;
      26:       63 34 18 00 00 00 00 00 *(u32 *)(r4 + 0x18) = r3
      27:       07 04 00 00 18 00 00 00 r4 += 0x18
;     bpf_printk("Hello World %d at %d", data->x, data);
      28:       18 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 r1 = 0x0 ll
      30:       b7 02 00 00 15 00 00 00 r2 = 0x15
      31:       85 00 00 00 06 00 00 00 call 0x6
      32:       b7 01 00 00 01 00 00 00 r1 = 0x1
;     __sync_fetch_and_add(&counter, 1);
      33:       c3 16 00 00 00 00 00 00 lock *(u32 *)(r6 + 0x0) += r1
;     return XDP_PASS;
      34:       b7 00 00 00 02 00 00 00 r0 = 0x2
      35:       95 00 00 00 00 00 00 00 exit
```
</details>

* Load `hello.bpf.o` via `sudo bpftool prog load hello.bpf.o /sys/fs/bpf/hello`




Next steps
* lock free
* use per cpu map
* reduce size of block
