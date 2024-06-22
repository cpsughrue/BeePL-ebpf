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
  <summary>Beginning of an simple implementation</summary>

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
static struct block *free_list = NULL;

void initialize_pool() {
    free_list = (struct block *)pool;
    free_list->size = POOL_SIZE - sizeof(struct block);
    free_list->free = true;
    free_list->next = NULL;
}

void *static_malloc(size_t size){
    if(free_list == NULL) initialize_pool();
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
    counter++; 
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
;     free_list = (struct block *)pool;
       0:       18 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 r1 = 0x0 ll
       2:       b7 02 00 00 00 00 00 00 r2 = 0x0
;     free_list->next = NULL;
       3:       7b 21 10 00 00 00 00 00 *(u64 *)(r1 + 0x10) = r2
       4:       b7 02 00 00 01 00 00 00 r2 = 0x1
;     free_list->free = true;
       5:       73 21 08 00 00 00 00 00 *(u8 *)(r1 + 0x8) = r2
       6:       b7 02 00 00 e8 03 00 00 r2 = 0x3e8
;     free_list->size = POOL_SIZE - sizeof(struct block);
       7:       7b 21 00 00 00 00 00 00 *(u64 *)(r1 + 0x0) = r2
;     free_list = (struct block *)pool;
       8:       18 02 00 00 00 04 00 00 00 00 00 00 00 00 00 00 r2 = 0x400 ll
      10:       7b 12 00 00 00 00 00 00 *(u64 *)(r2 + 0x0) = r1
; }
      11:       95 00 00 00 00 00 00 00 exit

0000000000000060 <static_malloc>:
;     if(free_list == NULL) initialize_pool();
      12:       18 01 00 00 00 04 00 00 00 00 00 00 00 00 00 00 r1 = 0x400 ll
      14:       79 10 00 00 00 00 00 00 r0 = *(u64 *)(r1 + 0x0)
      15:       55 00 07 00 00 00 00 00 if r0 != 0x0 goto +0x7 <LBB1_2>
;     free_list = (struct block *)pool;
      16:       18 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 r0 = 0x0 ll
      18:       b7 02 00 00 00 00 00 00 r2 = 0x0
;     free_list->next = NULL;
      19:       7b 20 10 00 00 00 00 00 *(u64 *)(r0 + 0x10) = r2
      20:       b7 02 00 00 e8 03 00 00 r2 = 0x3e8
;     free_list->size = POOL_SIZE - sizeof(struct block);
      21:       7b 20 00 00 00 00 00 00 *(u64 *)(r0 + 0x0) = r2
;     free_list = (struct block *)pool;
      22:       7b 01 00 00 00 00 00 00 *(u64 *)(r1 + 0x0) = r0

00000000000000b8 <LBB1_2>:
;     free_list->free = false;
      23:       18 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 r1 = 0x0 ll
      25:       b7 02 00 00 00 00 00 00 r2 = 0x0
      26:       73 21 08 00 00 00 00 00 *(u8 *)(r1 + 0x8) = r2
;     return (void *)((uint8_t *)free_list + sizeof(struct block));
      27:       07 00 00 00 18 00 00 00 r0 += 0x18
      28:       95 00 00 00 00 00 00 00 exit

Disassembly of section xdp:

0000000000000000 <hello>:
;     if(free_list == NULL) initialize_pool();
       0:       18 01 00 00 00 04 00 00 00 00 00 00 00 00 00 00 r1 = 0x400 ll
       2:       79 14 00 00 00 00 00 00 r4 = *(u64 *)(r1 + 0x0)
       3:       55 04 07 00 00 00 00 00 if r4 != 0x0 goto +0x7 <LBB2_2>
;     free_list = (struct block *)pool;
       4:       18 04 00 00 00 00 00 00 00 00 00 00 00 00 00 00 r4 = 0x0 ll
       6:       b7 02 00 00 00 00 00 00 r2 = 0x0
;     free_list->next = NULL;
       7:       7b 24 10 00 00 00 00 00 *(u64 *)(r4 + 0x10) = r2
       8:       b7 02 00 00 e8 03 00 00 r2 = 0x3e8
;     free_list->size = POOL_SIZE - sizeof(struct block);
       9:       7b 24 00 00 00 00 00 00 *(u64 *)(r4 + 0x0) = r2
;     free_list = (struct block *)pool;
      10:       7b 41 00 00 00 00 00 00 *(u64 *)(r1 + 0x0) = r4

0000000000000058 <LBB2_2>:
;     free_list->free = false;
      11:       18 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 r1 = 0x0 ll
      13:       b7 02 00 00 00 00 00 00 r2 = 0x0
      14:       73 21 08 00 00 00 00 00 *(u8 *)(r1 + 0x8) = r2
;     data->x = counter;
      15:       18 06 00 00 00 00 00 00 00 00 00 00 00 00 00 00 r6 = 0x0 ll
;     bpf_printk("Hello World %d at %d", data->x, data);
      17:       61 63 00 00 00 00 00 00 r3 = *(u32 *)(r6 + 0x0)
;     data->x = counter;
      18:       63 34 18 00 00 00 00 00 *(u32 *)(r4 + 0x18) = r3
;     return (void *)((uint8_t *)free_list + sizeof(struct block));
      19:       07 04 00 00 18 00 00 00 r4 += 0x18
;     bpf_printk("Hello World %d at %d", data->x, data);
      20:       18 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 r1 = 0x0 ll
      22:       b7 02 00 00 15 00 00 00 r2 = 0x15
      23:       85 00 00 00 06 00 00 00 call 0x6
;     counter++; 
      24:       61 61 00 00 00 00 00 00 r1 = *(u32 *)(r6 + 0x0)
      25:       07 01 00 00 01 00 00 00 r1 += 0x1
      26:       63 16 00 00 00 00 00 00 *(u32 *)(r6 + 0x0) = r1
;     return XDP_PASS;
      27:       b7 00 00 00 02 00 00 00 r0 = 0x2
      28:       95 00 00 00 00 00 00 00 exit
```
</details>

* Load `hello.bpf.o` via `sudo bpftool prog load hello.bpf.o /sys/fs/bpf/hello` results in `R3 invalid mem access 'scalar'`

<details>
  <summary>full error output</summary>

```
libbpf: prog 'hello': BPF program load failed: Permission denied
libbpf: prog 'hello': -- BEGIN PROG LOAD LOG --
0: R1=ctx(off=0,imm=0) R10=fp0
; if(free_list == NULL) initialize_pool();
0: (18) r1 = 0xffffc13e08da2400       ; R1_w=map_value(off=1024,ks=4,vs=1036,imm=0)
2: (79) r4 = *(u64 *)(r1 +0)          ; R1_w=map_value(off=1024,ks=4,vs=1036,imm=0) R4_w=scalar()
; if(free_list == NULL) initialize_pool();
3: (55) if r4 != 0x0 goto pc+7 11: R1_w=map_value(off=1024,ks=4,vs=1036,imm=0) R4_w=scalar() R10=fp0
; free_list->free = false;
11: (18) r1 = 0xffffc13e08da2000      ; R1_w=map_value(off=0,ks=4,vs=1036,imm=0)
13: (b7) r2 = 0                       ; R2_w=0
14: (73) *(u8 *)(r1 +8) = r2          ; R1_w=map_value(off=0,ks=4,vs=1036,imm=0) R2_w=0
; data->x = counter;
15: (18) r6 = 0xffffc13e08da2408      ; R6_w=map_value(off=1032,ks=4,vs=1036,imm=0)
; bpf_printk("Hello World %d at %d", data->x, data);
17: (61) r3 = *(u32 *)(r6 +0)         ; R3_w=scalar(umax=4294967295,var_off=(0x0; 0xffffffff)) R6_w=map_value(off=1032,ks=4,vs=1036,imm=0)
; data->x = counter;
18: (63) *(u32 *)(r4 +24) = r3
R4 invalid mem access 'scalar'
processed 30 insns (limit 1000000) max_states_per_insn 0 total_states 1 peak_states 1 mark_read 1
-- END PROG LOAD LOG --
libbpf: prog 'hello': failed to load: -13
libbpf: failed to load object 'hello.bpf.o'
Error: failed to load object file
```
</details>

Interestingly if `static_malloc` returns an offset of `pool` instead of `free_list` (both refer to same area of memory) the program is accepted by the eBPF verifier.

<details>
  <summary>Beginning of an simple implementation (accepted)</summary>

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
static struct block *free_list = NULL;

void initialize_pool() {
    free_list = (struct block *)pool;
    free_list->size = POOL_SIZE - sizeof(struct block);
    free_list->free = true;
    free_list->next = NULL;
}

void *static_malloc(size_t size){
    if(free_list == NULL) initialize_pool();
    free_list->free = false;
    return (void *)((uint8_t *)pool + sizeof(struct block));
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
    counter++; 
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

```
</details>

