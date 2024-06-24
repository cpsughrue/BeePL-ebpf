# Emulating `malloc` and `free` in eBPF   

The goal of this experiment is to take the program below and replace `malloc` with a custom allocator `static_malloc` such that it will be accepted by the eBPF verifier. Idealy `static_malloc` should emulate `malloc` such that any invalid eBPF program can be made valid by replacing all instance of `malloc` with `static_malloc` and including a single headerfile.

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


### Allocator Implementatino

I did some reading on allocator design and based my implementation on a linked list allocator that uses a large array of `uint8_t` as its memory pool. I wrote a bare bones implementation outside eBPF to more easily test functionality then began porting the code to an eBPF program. I am almost done porting `static_malloc`. The eBPF verifier messages are pretty cryptic but I am starting to get a handle on it. In the program below `num_blocks++` is causing the eBPF verifier to reject the program. If you comment out `num_blocks++` then the program get accepted. 

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
                // curr is large enogh to split into two blocks
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
```
</details>

* Compile with `clang -target bpf -g -O2 -o hello.bpf.o -c hello.bpf.c`. 
* Dump object file with `llvm-objdump -S hello.bpf.o`

<details>
  <summary>object file</summary>

```
hello.bpf.o:	file format elf64-bpf

Disassembly of section .text:

0000000000000000 <initialize_pool>:
;     list->size = POOL_SIZE - sizeof(struct block);
       0:	18 01 00 00 10 00 00 00 00 00 00 00 00 00 00 00	r1 = 0x10 ll
       2:	b7 02 00 00 00 00 00 00	r2 = 0x0
;     list->next = NULL;
       3:	7b 21 10 00 00 00 00 00	*(u64 *)(r1 + 0x10) = r2
       4:	b7 02 00 00 e8 03 00 00	r2 = 0x3e8
;     list->size = POOL_SIZE - sizeof(struct block);
       5:	7b 21 00 00 00 00 00 00	*(u64 *)(r1 + 0x0) = r2
       6:	b7 02 00 00 01 00 00 00	r2 = 0x1
;     list->free = true;
       7:	73 21 08 00 00 00 00 00	*(u8 *)(r1 + 0x8) = r2
;     is_initialized = true;
       8:	18 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00	r1 = 0x0 ll
      10:	73 21 00 00 00 00 00 00	*(u8 *)(r1 + 0x0) = r2
; }
      11:	95 00 00 00 00 00 00 00	exit

0000000000000060 <static_malloc>:
;     if(is_initialized == false) initialize_pool();
      12:	18 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00	r2 = 0x0 ll
      14:	71 23 00 00 00 00 00 00	r3 = *(u8 *)(r2 + 0x0)
      15:	55 03 09 00 00 00 00 00	if r3 != 0x0 goto +0x9 <LBB1_2>
;     list->size = POOL_SIZE - sizeof(struct block);
      16:	18 03 00 00 10 00 00 00 00 00 00 00 00 00 00 00	r3 = 0x10 ll
      18:	b7 04 00 00 00 00 00 00	r4 = 0x0
;     list->next = NULL;
      19:	7b 43 10 00 00 00 00 00	*(u64 *)(r3 + 0x10) = r4
      20:	b7 04 00 00 e8 03 00 00	r4 = 0x3e8
;     list->size = POOL_SIZE - sizeof(struct block);
      21:	7b 43 00 00 00 00 00 00	*(u64 *)(r3 + 0x0) = r4
      22:	b7 04 00 00 01 00 00 00	r4 = 0x1
;     list->free = true;
      23:	73 43 08 00 00 00 00 00	*(u8 *)(r3 + 0x8) = r4
;     is_initialized = true;
      24:	73 42 00 00 00 00 00 00	*(u8 *)(r2 + 0x0) = r4

00000000000000c8 <LBB1_2>:
      25:	b7 00 00 00 00 00 00 00	r0 = 0x0
      26:	18 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00	r2 = 0x0 ll
      28:	79 23 00 00 00 00 00 00	r3 = *(u64 *)(r2 + 0x0)
;     for(int i = 0; i < num_blocks; i++) {
      29:	15 03 07 00 00 00 00 00	if r3 == 0x0 goto +0x7 <LBB1_10>
      30:	18 02 00 00 10 00 00 00 00 00 00 00 00 00 00 00	r2 = 0x10 ll
      32:	b7 04 00 00 00 00 00 00	r4 = 0x0
      33:	05 00 04 00 00 00 00 00	goto +0x4 <LBB1_4>

0000000000000110 <LBB1_9>:
;         curr = curr->next;
      34:	79 22 10 00 00 00 00 00	r2 = *(u64 *)(r2 + 0x10)
;     for(int i = 0; i < num_blocks; i++) {
      35:	07 04 00 00 01 00 00 00	r4 += 0x1
      36:	2d 43 01 00 00 00 00 00	if r3 > r4 goto +0x1 <LBB1_4>

0000000000000128 <LBB1_10>:
; }
      37:	95 00 00 00 00 00 00 00	exit

0000000000000130 <LBB1_4>:
;         if(curr->free == true && curr->size >= size){
      38:	71 25 08 00 00 00 00 00	r5 = *(u8 *)(r2 + 0x8)
      39:	15 05 fa ff 00 00 00 00	if r5 == 0x0 goto -0x6 <LBB1_9>
      40:	79 25 00 00 00 00 00 00	r5 = *(u64 *)(r2 + 0x0)
      41:	2d 51 f8 ff 00 00 00 00	if r1 > r5 goto -0x8 <LBB1_9>
;             if(curr->size <= size + sizeof(struct block)) {
      42:	bf 14 00 00 00 00 00 00	r4 = r1
      43:	07 04 00 00 18 00 00 00	r4 += 0x18
      44:	3d 54 10 00 00 00 00 00	if r4 >= r5 goto +0x10 <LBB1_8>
;                 struct block *new_block = (struct block *)((uint8_t *)curr + size + sizeof(struct block));
      45:	bf 24 00 00 00 00 00 00	r4 = r2
      46:	0f 14 00 00 00 00 00 00	r4 += r1
      47:	b7 00 00 00 01 00 00 00	r0 = 0x1
;                 new_block->free = true;
      48:	73 04 20 00 00 00 00 00	*(u8 *)(r4 + 0x20) = r0
;                 new_block->size = curr->size - size - sizeof(struct block);
      49:	1f 15 00 00 00 00 00 00	r5 -= r1
      50:	07 05 00 00 e8 ff ff ff	r5 += -0x18
      51:	7b 54 18 00 00 00 00 00	*(u64 *)(r4 + 0x18) = r5
;                 new_block->next = curr->next;
      52:	79 25 10 00 00 00 00 00	r5 = *(u64 *)(r2 + 0x10)
      53:	7b 54 28 00 00 00 00 00	*(u64 *)(r4 + 0x28) = r5
;                 struct block *new_block = (struct block *)((uint8_t *)curr + size + sizeof(struct block));
      54:	07 04 00 00 18 00 00 00	r4 += 0x18
;                 curr->next = new_block;
      55:	7b 42 10 00 00 00 00 00	*(u64 *)(r2 + 0x10) = r4
;                 curr->size = size;
      56:	7b 12 00 00 00 00 00 00	*(u64 *)(r2 + 0x0) = r1
;                 num_blocks++;
      57:	07 03 00 00 01 00 00 00	r3 += 0x1
      58:	18 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00	r1 = 0x0 ll
      60:	7b 31 00 00 00 00 00 00	*(u64 *)(r1 + 0x0) = r3

00000000000001e8 <LBB1_8>:
      61:	b7 01 00 00 00 00 00 00	r1 = 0x0
      62:	73 12 08 00 00 00 00 00	*(u8 *)(r2 + 0x8) = r1
;             return (void *)((uint8_t *)curr + sizeof(struct block));
      63:	07 02 00 00 18 00 00 00	r2 += 0x18
      64:	bf 20 00 00 00 00 00 00	r0 = r2
      65:	05 00 e3 ff 00 00 00 00	goto -0x1d <LBB1_10>

Disassembly of section xdp:

0000000000000000 <hello>:
;     bpf_spin_lock(&lock);
       0:	18 01 00 00 08 00 00 00 00 00 00 00 00 00 00 00	r1 = 0x8 ll
       2:	85 00 00 00 5d 00 00 00	call 0x5d
;     if(is_initialized == false) initialize_pool();
       3:	18 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00	r1 = 0x0 ll
       5:	71 12 00 00 00 00 00 00	r2 = *(u8 *)(r1 + 0x0)
       6:	55 02 09 00 00 00 00 00	if r2 != 0x0 goto +0x9 <LBB2_2>
;     list->size = POOL_SIZE - sizeof(struct block);
       7:	18 02 00 00 10 00 00 00 00 00 00 00 00 00 00 00	r2 = 0x10 ll
       9:	b7 03 00 00 00 00 00 00	r3 = 0x0
;     list->next = NULL;
      10:	7b 32 10 00 00 00 00 00	*(u64 *)(r2 + 0x10) = r3
      11:	b7 03 00 00 e8 03 00 00	r3 = 0x3e8
;     list->size = POOL_SIZE - sizeof(struct block);
      12:	7b 32 00 00 00 00 00 00	*(u64 *)(r2 + 0x0) = r3
      13:	b7 03 00 00 01 00 00 00	r3 = 0x1
;     list->free = true;
      14:	73 32 08 00 00 00 00 00	*(u8 *)(r2 + 0x8) = r3
;     is_initialized = true;
      15:	73 31 00 00 00 00 00 00	*(u8 *)(r1 + 0x0) = r3

0000000000000080 <LBB2_2>:
      16:	18 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00	r1 = 0x0 ll
      18:	79 11 00 00 00 00 00 00	r1 = *(u64 *)(r1 + 0x0)
;     for(int i = 0; i < num_blocks; i++) {
      19:	15 01 27 00 00 00 00 00	if r1 == 0x0 goto +0x27 <LBB2_9>
      20:	18 02 00 00 10 00 00 00 00 00 00 00 00 00 00 00	r2 = 0x10 ll
      22:	b7 03 00 00 00 00 00 00	r3 = 0x0
      23:	b7 04 00 00 08 00 00 00	r4 = 0x8
      24:	05 00 04 00 00 00 00 00	goto +0x4 <LBB2_4>

00000000000000c8 <LBB2_11>:
;         curr = curr->next;
      25:	79 22 10 00 00 00 00 00	r2 = *(u64 *)(r2 + 0x10)
;     for(int i = 0; i < num_blocks; i++) {
      26:	07 03 00 00 01 00 00 00	r3 += 0x1
      27:	2d 31 01 00 00 00 00 00	if r1 > r3 goto +0x1 <LBB2_4>
      28:	05 00 1e 00 00 00 00 00	goto +0x1e <LBB2_9>

00000000000000e8 <LBB2_4>:
;         if(curr->free == true && curr->size >= size){
      29:	71 25 08 00 00 00 00 00	r5 = *(u8 *)(r2 + 0x8)
      30:	15 05 fa ff 00 00 00 00	if r5 == 0x0 goto -0x6 <LBB2_11>
      31:	79 25 00 00 00 00 00 00	r5 = *(u64 *)(r2 + 0x0)
      32:	2d 54 f8 ff 00 00 00 00	if r4 > r5 goto -0x8 <LBB2_11>
      33:	b7 03 00 00 21 00 00 00	r3 = 0x21
;             if(curr->size <= size + sizeof(struct block)) {
      34:	2d 53 0f 00 00 00 00 00	if r3 > r5 goto +0xf <LBB2_8>
      35:	b7 03 00 00 01 00 00 00	r3 = 0x1
;                 new_block->free = true;
      36:	73 32 28 00 00 00 00 00	*(u8 *)(r2 + 0x28) = r3
      37:	b7 03 00 00 08 00 00 00	r3 = 0x8
;                 curr->size = size;
      38:	7b 32 00 00 00 00 00 00	*(u64 *)(r2 + 0x0) = r3
;                 new_block->size = curr->size - size - sizeof(struct block);
      39:	07 05 00 00 e0 ff ff ff	r5 += -0x20
      40:	7b 52 20 00 00 00 00 00	*(u64 *)(r2 + 0x20) = r5
;                 new_block->next = curr->next;
      41:	79 23 10 00 00 00 00 00	r3 = *(u64 *)(r2 + 0x10)
;                 struct block *new_block = (struct block *)((uint8_t *)curr + size + sizeof(struct block));
      42:	bf 24 00 00 00 00 00 00	r4 = r2
      43:	07 04 00 00 20 00 00 00	r4 += 0x20
;                 curr->next = new_block;
      44:	7b 42 10 00 00 00 00 00	*(u64 *)(r2 + 0x10) = r4
;                 new_block->next = curr->next;
      45:	7b 32 30 00 00 00 00 00	*(u64 *)(r2 + 0x30) = r3
;                 num_blocks++;
      46:	07 01 00 00 01 00 00 00	r1 += 0x1
      47:	18 03 00 00 00 00 00 00 00 00 00 00 00 00 00 00	r3 = 0x0 ll
      49:	7b 13 00 00 00 00 00 00	*(u64 *)(r3 + 0x0) = r1

0000000000000190 <LBB2_8>:
      50:	b7 01 00 00 00 00 00 00	r1 = 0x0
      51:	73 12 08 00 00 00 00 00	*(u8 *)(r2 + 0x8) = r1
;     bpf_spin_unlock(&lock);
      52:	18 01 00 00 08 00 00 00 00 00 00 00 00 00 00 00	r1 = 0x8 ll
      54:	85 00 00 00 5e 00 00 00	call 0x5e
;         bpf_printk("valid block found");
      55:	18 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00	r1 = 0x0 ll
      57:	b7 02 00 00 12 00 00 00	r2 = 0x12
      58:	05 00 06 00 00 00 00 00	goto +0x6 <LBB2_10>

00000000000001d8 <LBB2_9>:
;     bpf_spin_unlock(&lock);
      59:	18 01 00 00 08 00 00 00 00 00 00 00 00 00 00 00	r1 = 0x8 ll
      61:	85 00 00 00 5e 00 00 00	call 0x5e
;         bpf_printk("invalid block found");
      62:	18 01 00 00 12 00 00 00 00 00 00 00 00 00 00 00	r1 = 0x12 ll
      64:	b7 02 00 00 14 00 00 00	r2 = 0x14

0000000000000208 <LBB2_10>:
      65:	85 00 00 00 06 00 00 00	call 0x6
;     bpf_printk("Hello World %d", counter);
      66:	18 06 00 00 00 00 00 00 00 00 00 00 00 00 00 00	r6 = 0x0 ll
      68:	61 63 00 00 00 00 00 00	r3 = *(u32 *)(r6 + 0x0)
      69:	18 01 00 00 26 00 00 00 00 00 00 00 00 00 00 00	r1 = 0x26 ll
      71:	b7 02 00 00 0f 00 00 00	r2 = 0xf
      72:	85 00 00 00 06 00 00 00	call 0x6
      73:	b7 01 00 00 01 00 00 00	r1 = 0x1
;     __sync_fetch_and_add(&counter, 1);
      74:	c3 16 00 00 00 00 00 00	lock *(u32 *)(r6 + 0x0) += r1
;     return XDP_PASS;
      75:	b7 00 00 00 02 00 00 00	r0 = 0x2
      76:	95 00 00 00 00 00 00 00	exit
```
</details>

* Load `hello.bpf.o` via `sudo bpftool prog load hello.bpf.o /sys/fs/bpf/hello`

<details>
  <summary>error</summary>

```
[cpsughrue@localhost chapter3]$ sudo bpftool prog load hello.bpf.o /sys/fs/bpf/hello
libbpf: prog 'hello': BPF program load failed: Permission denied
libbpf: prog 'hello': -- BEGIN PROG LOAD LOG --
0: R1=ctx(off=0,imm=0) R10=fp0
; bpf_spin_lock(&lock);
0: (18) r1 = 0xffffaf630b3a2008       ; R1_w=map_value(off=8,ks=4,vs=1040,imm=0)
2: (85) call bpf_spin_lock#93         ;
; if(is_initialized == false) initialize_pool();
3: (18) r1 = 0xffffaf630b3a2000       ; R1_w=map_value(off=0,ks=4,vs=1040,imm=0)
5: (71) r2 = *(u8 *)(r1 +0)           ; R1_w=map_value(off=0,ks=4,vs=1040,imm=0) R2_w=scalar(umax=255,var_off=(0x0; 0xff))
; if(is_initialized == false) initialize_pool();
6: (55) if r2 != 0x0 goto pc+9        ; R2_w=0
; list->size = POOL_SIZE - sizeof(struct block);
7: (18) r2 = 0xffffaf630b3a2010       ; R2_w=map_value(off=16,ks=4,vs=1040,imm=0)
9: (b7) r3 = 0                        ; R3_w=0
; list->next = NULL;
10: (7b) *(u64 *)(r2 +16) = r3        ; R2_w=map_value(off=16,ks=4,vs=1040,imm=0) R3_w=0
11: (b7) r3 = 1000                    ; R3_w=1000
; list->size = POOL_SIZE - sizeof(struct block);
12: (7b) *(u64 *)(r2 +0) = r3         ; R2_w=map_value(off=16,ks=4,vs=1040,imm=0) R3_w=1000
13: (b7) r3 = 1                       ; R3_w=1
; list->free = true;
14: (73) *(u8 *)(r2 +8) = r3          ; R2_w=map_value(off=16,ks=4,vs=1040,imm=0) R3_w=1
; is_initialized = true;
15: (73) *(u8 *)(r1 +0) = r3          ; R1=map_value(off=0,ks=4,vs=1040,imm=0) R3=1
16: (18) r1 = 0xffff9cd1431b8510      ; R1_w=map_value(off=0,ks=4,vs=8,imm=0)
18: (79) r1 = *(u64 *)(r1 +0)         ; R1_w=scalar()
; for(int i = 0; i < num_blocks; i++) {
19: (15) if r1 == 0x0 goto pc+39      ; R1_w=scalar()
20: (18) r2 = 0xffffaf630b3a2010      ; R2_w=map_value(off=16,ks=4,vs=1040,imm=0)
22: (b7) r3 = 0                       ; R3_w=0
23: (b7) r4 = 8                       ; R4_w=8
24: (05) goto pc+4
; if(curr->free == true && curr->size >= size){
29: (71) r5 = *(u8 *)(r2 +8)          ; R2=map_value(off=16,ks=4,vs=1040,imm=0) R5=scalar(umax=255,var_off=(0x0; 0xff))
; if(curr->free == true && curr->size >= size){
30: (15) if r5 == 0x0 goto pc-6       ; R5=scalar(umax=255,var_off=(0x0; 0xff))
; if(curr->free == true && curr->size >= size){
31: (79) r5 = *(u64 *)(r2 +0)         ; R2=map_value(off=16,ks=4,vs=1040,imm=0) R5_w=scalar()
; if(curr->free == true && curr->size >= size){
32: (2d) if r4 > r5 goto pc-8 25: R1=scalar() R2=map_value(off=16,ks=4,vs=1040,imm=0) R3=0 R4=8 R5=scalar(umax=7,var_off=(0x0; 0x7)) R10=fp0
; curr = curr->next;
25: (79) r2 = *(u64 *)(r2 +16)        ; R2_w=scalar()
; for(int i = 0; i < num_blocks; i++) {
26: (07) r3 += 1                      ; R3_w=1
; for(int i = 0; i < num_blocks; i++) {
27: (2d) if r1 > r3 goto pc+1 29: R1=scalar(umin=2) R2_w=scalar() R3_w=1 R4=8 R5=scalar(umax=7,var_off=(0x0; 0x7)) R10=fp0
; if(curr->free == true && curr->size >= size){
29: (71) r5 = *(u8 *)(r2 +8)
R2 invalid mem access 'scalar'
processed 69 insns (limit 1000000) max_states_per_insn 0 total_states 6 peak_states 6 mark_read 2
-- END PROG LOAD LOG --
libbpf: prog 'hello': failed to load: -13
libbpf: failed to load object 'hello.bpf.o'
Error: failed to load object file
```
</details>


### Next steps

* I am going to find a few hours to identify the root cause of the above eBPF verifer error message. There may be a simple work around. In my experience a fix to appease the verifer is often pretty small and simple. The tricky part is tracking down the root cause. If there is no simple fix I have an idea for how to remove the need for the `num_blocks` variable which I will try out.

* I would like to place `memory_pool` in a `BPF_MAP_TYPE_PERCPU_HASH` which will help solve some of the thread safety challenges I have been working around. This should be a pretty easy change.

* Of course I will also port `static_free` to the eBPF program and make any modification to ensure it gets accepted by the verifier.
