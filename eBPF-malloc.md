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

### Program as is

To start what happens when we try to load the program as is? 

* Compile, with zero optimizations so the `malloc` does not get removed, via the command line `clang -target bpf -g -O0 -o hello.bpf.o -c hello.bpf.c`. 
* Dump object file with `llvm-objdump -S hello.bpf.o`

<details>
  <summary>object file</summary>

```
hello.bpf.o:    file format elf64-bpf

Disassembly of section xdp:

0000000000000000 <hello>:
; int hello(struct xdp_md *ctx) {
       0:       7b 1a f8 ff 00 00 00 00 *(u64 *)(r10 - 0x8) = r1
       1:       b7 01 00 00 02 00 00 00 r1 = 0x2
;     vec2_t *data = (vec2_t *)malloc(sizeof(vec2_t));
       2:       7b 1a e0 ff 00 00 00 00 *(u64 *)(r10 - 0x20) = r1
       3:       85 10 00 00 ff ff ff ff call -0x1
       4:       7b 0a f0 ff 00 00 00 00 *(u64 *)(r10 - 0x10) = r0
;     bpf_printk("Hello World %d", counter);
       5:       18 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 r1 = 0x0 ll
       7:       7b 1a d8 ff 00 00 00 00 *(u64 *)(r10 - 0x28) = r1
       8:       61 13 00 00 00 00 00 00 r3 = *(u32 *)(r1 + 0x0)
       9:       18 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 r1 = 0x0 ll
      11:       b7 02 00 00 0f 00 00 00 r2 = 0xf
      12:       85 00 00 00 06 00 00 00 call 0x6
      13:       79 a2 d8 ff 00 00 00 00 r2 = *(u64 *)(r10 - 0x28)
      14:       bf 01 00 00 00 00 00 00 r1 = r0
      15:       79 a0 e0 ff 00 00 00 00 r0 = *(u64 *)(r10 - 0x20)
      16:       7b 1a e8 ff 00 00 00 00 *(u64 *)(r10 - 0x18) = r1
;     counter++; 
      17:       61 21 00 00 00 00 00 00 r1 = *(u32 *)(r2 + 0x0)
      18:       07 01 00 00 01 00 00 00 r1 += 0x1
      19:       63 12 00 00 00 00 00 00 *(u32 *)(r2 + 0x0) = r1
;     return XDP_PASS;
      20:       95 00 00 00 00 00 00 00 exit
```
</details>

* Load `hello.bpf.o` via `sudo bpftool prog load hello.bpf.o /sys/fs/bpf/hello` results in `libbpf: failed to find BTF for extern 'malloc' [11] section: -2`


### Linked list allocator

First instinct is to implement a linked list allocator.

<details>
  <summary>Beginning of an simple implementation</summary>

```c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>

#define POOL_SIZE 1024

struct block {
    size_t size;
    bool free;
    struct block *next;
};

static uint8_t pool[POOL_SIZE];
static struct block *free_list = NULL;
static uint64_t number_free_blocks = 1; // start with entire pool being free

void initialize_pool() {
    free_list = (struct block *)pool;
    free_list->size = POOL_SIZE - sizeof(struct block);
    free_list->free = true;
    free_list->next = NULL;
}

void *static_malloc(size_t size) {
    if(free_list == NULL) initialize_pool();
    
    struct block *curr = free_list;

    // for loop accepted by eBPF verifier 
    for(uint64_t i = 0; i < number_free_blocks; i++){
        if(curr->free == true && curr->size >= (size + sizeof(struct block))){
            curr->free = false;
            // skip the meta data and return a pointer to the first byte of usable memory
            return (void *)((uint8_t *)curr + sizeof(struct block)); 
        }
    }
    return NULL;
}

//==============================================================================
//==============================================================================

typedef struct vec2 {
    uint8_t x;
    uint8_t y;
} vec2_t;

int counter = 0;

SEC("xdp")
int hello(struct xdp_md *ctx) {
    vec2_t *data = (vec2_t *)static_malloc(sizeof(vec2_t));

    bpf_printk("Hello World %d", counter);
    counter++; 
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
```
</details>

* Compile, with zero optimizations so the `malloc` does not get removed, via the command line `clang -target bpf -g -O0 -o hello.bpf.o -c hello.bpf.c`. 
* Dump object file with `llvm-objdump -S hello.bpf.o`

<details>
  <summary>object file</summary>

```
hello.bpf.o:    file format elf64-bpf

Disassembly of section .text:

0000000000000000 <initialize_pool>:
;     free_list = (struct block *)pool;
       0:       18 01 00 00 00 04 00 00 00 00 00 00 00 00 00 00 r1 = 0x400 ll
       2:       18 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 r2 = 0x0 ll
       4:       7b 21 00 00 00 00 00 00 *(u64 *)(r1 + 0x0) = r2
;     free_list->size = POOL_SIZE - sizeof(struct block);
       5:       79 13 00 00 00 00 00 00 r3 = *(u64 *)(r1 + 0x0)
       6:       b7 02 00 00 e8 03 00 00 r2 = 0x3e8
       7:       7b 23 00 00 00 00 00 00 *(u64 *)(r3 + 0x0) = r2
;     free_list->free = true;
       8:       79 13 00 00 00 00 00 00 r3 = *(u64 *)(r1 + 0x0)
       9:       b7 02 00 00 01 00 00 00 r2 = 0x1
      10:       73 23 08 00 00 00 00 00 *(u8 *)(r3 + 0x8) = r2
;     free_list->next = NULL;
      11:       79 12 00 00 00 00 00 00 r2 = *(u64 *)(r1 + 0x0)
      12:       b7 01 00 00 00 00 00 00 r1 = 0x0
      13:       7b 12 10 00 00 00 00 00 *(u64 *)(r2 + 0x10) = r1
; }
      14:       95 00 00 00 00 00 00 00 exit

0000000000000078 <static_malloc>:
; void *static_malloc(size_t size) {
      15:       7b 1a f0 ff 00 00 00 00 *(u64 *)(r10 - 0x10) = r1
;     if(free_list == NULL) initialize_pool();
      16:       18 01 00 00 00 04 00 00 00 00 00 00 00 00 00 00 r1 = 0x400 ll
      18:       79 11 00 00 00 00 00 00 r1 = *(u64 *)(r1 + 0x0)
      19:       55 01 03 00 00 00 00 00 if r1 != 0x0 goto +0x3 <LBB1_2>
      20:       05 00 00 00 00 00 00 00 goto +0x0 <LBB1_1>

00000000000000a8 <LBB1_1>:
      21:       85 10 00 00 ff ff ff ff call -0x1
      22:       05 00 00 00 00 00 00 00 goto +0x0 <LBB1_2>

00000000000000b8 <LBB1_2>:
;     struct block *curr = free_list;
      23:       18 01 00 00 00 04 00 00 00 00 00 00 00 00 00 00 r1 = 0x400 ll
      25:       79 11 00 00 00 00 00 00 r1 = *(u64 *)(r1 + 0x0)
      26:       7b 1a e8 ff 00 00 00 00 *(u64 *)(r10 - 0x18) = r1
      27:       b7 01 00 00 00 00 00 00 r1 = 0x0
;     for(uint64_t i = 0; i < number_free_blocks; i++){
      28:       7b 1a e0 ff 00 00 00 00 *(u64 *)(r10 - 0x20) = r1
      29:       05 00 00 00 00 00 00 00 goto +0x0 <LBB1_3>

00000000000000f0 <LBB1_3>:
      30:       79 a1 e0 ff 00 00 00 00 r1 = *(u64 *)(r10 - 0x20)
      31:       18 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 r2 = 0x0 ll
      33:       79 22 00 00 00 00 00 00 r2 = *(u64 *)(r2 + 0x0)
      34:       3d 21 18 00 00 00 00 00 if r1 >= r2 goto +0x18 <LBB1_9>
      35:       05 00 00 00 00 00 00 00 goto +0x0 <LBB1_4>

0000000000000120 <LBB1_4>:
;         if(curr->free == true && curr->size >= (size + sizeof(struct block))){
      36:       79 a1 e8 ff 00 00 00 00 r1 = *(u64 *)(r10 - 0x18)
      37:       71 11 08 00 00 00 00 00 r1 = *(u8 *)(r1 + 0x8)
      38:       57 01 00 00 01 00 00 00 r1 &= 0x1
      39:       15 01 0e 00 00 00 00 00 if r1 == 0x0 goto +0xe <LBB1_7>
      40:       05 00 00 00 00 00 00 00 goto +0x0 <LBB1_5>

0000000000000148 <LBB1_5>:
      41:       79 a1 e8 ff 00 00 00 00 r1 = *(u64 *)(r10 - 0x18)
      42:       79 12 00 00 00 00 00 00 r2 = *(u64 *)(r1 + 0x0)
      43:       79 a1 f0 ff 00 00 00 00 r1 = *(u64 *)(r10 - 0x10)
      44:       07 01 00 00 18 00 00 00 r1 += 0x18
      45:       2d 21 08 00 00 00 00 00 if r1 > r2 goto +0x8 <LBB1_7>
      46:       05 00 00 00 00 00 00 00 goto +0x0 <LBB1_6>

0000000000000178 <LBB1_6>:
;             curr->free = false;
      47:       79 a2 e8 ff 00 00 00 00 r2 = *(u64 *)(r10 - 0x18)
      48:       b7 01 00 00 00 00 00 00 r1 = 0x0
      49:       73 12 08 00 00 00 00 00 *(u8 *)(r2 + 0x8) = r1
;             return (void *)((uint8_t *)curr + sizeof(struct block)); 
      50:       79 a1 e8 ff 00 00 00 00 r1 = *(u64 *)(r10 - 0x18)
      51:       07 01 00 00 18 00 00 00 r1 += 0x18
      52:       7b 1a f8 ff 00 00 00 00 *(u64 *)(r10 - 0x8) = r1
      53:       05 00 08 00 00 00 00 00 goto +0x8 <LBB1_10>

00000000000001b0 <LBB1_7>:
;     }
      54:       05 00 00 00 00 00 00 00 goto +0x0 <LBB1_8>

00000000000001b8 <LBB1_8>:
;     for(uint64_t i = 0; i < number_free_blocks; i++){
      55:       79 a1 e0 ff 00 00 00 00 r1 = *(u64 *)(r10 - 0x20)
      56:       07 01 00 00 01 00 00 00 r1 += 0x1
      57:       7b 1a e0 ff 00 00 00 00 *(u64 *)(r10 - 0x20) = r1
      58:       05 00 e3 ff 00 00 00 00 goto -0x1d <LBB1_3>

00000000000001d8 <LBB1_9>:
      59:       b7 01 00 00 00 00 00 00 r1 = 0x0
;     return NULL;
      60:       7b 1a f8 ff 00 00 00 00 *(u64 *)(r10 - 0x8) = r1
      61:       05 00 00 00 00 00 00 00 goto +0x0 <LBB1_10>

00000000000001f0 <LBB1_10>:
; }
      62:       79 a0 f8 ff 00 00 00 00 r0 = *(u64 *)(r10 - 0x8)
      63:       95 00 00 00 00 00 00 00 exit

Disassembly of section xdp:

0000000000000000 <hello>:
; int hello(struct xdp_md *ctx) {
       0:       7b 1a f8 ff 00 00 00 00 *(u64 *)(r10 - 0x8) = r1
       1:       b7 01 00 00 02 00 00 00 r1 = 0x2
;     vec2_t *data = (vec2_t *)static_malloc(sizeof(vec2_t));
       2:       7b 1a e0 ff 00 00 00 00 *(u64 *)(r10 - 0x20) = r1
       3:       85 10 00 00 ff ff ff ff call -0x1
       4:       7b 0a f0 ff 00 00 00 00 *(u64 *)(r10 - 0x10) = r0
;     bpf_printk("Hello World %d", counter);
       5:       18 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 r1 = 0x0 ll
       7:       7b 1a d8 ff 00 00 00 00 *(u64 *)(r10 - 0x28) = r1
       8:       61 13 00 00 00 00 00 00 r3 = *(u32 *)(r1 + 0x0)
       9:       18 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 r1 = 0x0 ll
      11:       b7 02 00 00 0f 00 00 00 r2 = 0xf
      12:       85 00 00 00 06 00 00 00 call 0x6
      13:       79 a2 d8 ff 00 00 00 00 r2 = *(u64 *)(r10 - 0x28)
      14:       bf 01 00 00 00 00 00 00 r1 = r0
      15:       79 a0 e0 ff 00 00 00 00 r0 = *(u64 *)(r10 - 0x20)
      16:       7b 1a e8 ff 00 00 00 00 *(u64 *)(r10 - 0x18) = r1
;     counter++; 
      17:       61 21 00 00 00 00 00 00 r1 = *(u32 *)(r2 + 0x0)
      18:       07 01 00 00 01 00 00 00 r1 += 0x1
      19:       63 12 00 00 00 00 00 00 *(u32 *)(r2 + 0x0) = r1
;     return XDP_PASS;
      20:       95 00 00 00 00 00 00 00 exit
```
</details>

* Load `hello.bpf.o` via `sudo bpftool prog load hello.bpf.o /sys/fs/bpf/hello` results in `R3 invalid mem access 'scalar'`


<details>
  <summary>full error output</summary>

```
libbpf: BTF loading error: -22
libbpf: -- BEGIN BTF LOAD LOG ---
magic: 0xeb9f
version: 1
flags: 0x0
hdr_len: 24
type_off: 0
type_len: 756
str_off: 756
str_len: 1138
btf_total_size: 1918
[1] FUNC_PROTO (anon) return=0 args=(void)
[2] FUNC initialize_pool type_id=1
[3] FUNC_PROTO (anon) return=4 args=(5 (anon))
[4] PTR (anon) type_id=0
[5] TYPEDEF size_t type_id=6
[6] INT unsigned long size=8 bits_offset=0 nr_bits=64 encoding=(none)
[7] FUNC static_malloc type_id=3
[8] FUNC_PROTO (anon) return=9 args=(10 (anon))
[9] INT int size=4 bits_offset=0 nr_bits=32 encoding=SIGNED
[10] PTR (anon) type_id=11
[11] STRUCT xdp_md size=24 vlen=6
        data type_id=12 bits_offset=0
        data_end type_id=12 bits_offset=32
        data_meta type_id=12 bits_offset=64
        ingress_ifindex type_id=12 bits_offset=96
        rx_queue_index type_id=12 bits_offset=128
        egress_ifindex type_id=12 bits_offset=160
[12] TYPEDEF __u32 type_id=13
[13] INT unsigned int size=4 bits_offset=0 nr_bits=32 encoding=(none)
[14] FUNC hello type_id=8
[15] TYPEDEF uint8_t type_id=16
[16] TYPEDEF __uint8_t type_id=17
[17] INT unsigned char size=1 bits_offset=0 nr_bits=8 encoding=(none)
[18] ARRAY (anon) type_id=15 index_type_id=19 nr_elems=1024
[19] INT __ARRAY_SIZE_TYPE__ size=4 bits_offset=0 nr_bits=32 encoding=(none)
[20] VAR pool type_id=18 linkage=0
[21] PTR (anon) type_id=22
[22] STRUCT block size=24 vlen=3
        size type_id=5 bits_offset=0
        free type_id=23 bits_offset=64
        next type_id=21 bits_offset=128
[23] INT _Bool size=1 bits_offset=0 nr_bits=8 encoding=BOOL
[24] VAR free_list type_id=21 linkage=0
[25] TYPEDEF uint64_t type_id=26
[26] TYPEDEF __uint64_t type_id=27
[27] INT unsigned long long size=8 bits_offset=0 nr_bits=64 encoding=(none)
[28] VAR number_free_blocks type_id=25 linkage=0
[29] VAR counter type_id=9 linkage=1
[30] CONST (anon) type_id=31
[31] INT char size=1 bits_offset=0 nr_bits=8 encoding=SIGNED
[32] ARRAY (anon) type_id=30 index_type_id=19 nr_elems=15
[33] VAR hello.____fmt type_id=32 linkage=0
[34] ARRAY (anon) type_id=31 index_type_id=19 nr_elems=13
[35] VAR LICENSE type_id=34 linkage=1
[36] DATASEC .bss size=1036 vlen=3
         type_id=20 offset=0 size=1024
         type_id=24 offset=1024 size=8
         type_id=29 offset=1032 size=4
[37] DATASEC .data size=8 vlen=1
         type_id=28 offset=0 size=8
[38] DATASEC .rodata size=15 vlen=1
         type_id=33 offset=0 size=15
[39] DATASEC license size=13 vlen=1
         type_id=35 offset=0 size=13
[7] FUNC static_malloc type_id=3 Invalid arg#1

-- END BTF LOAD LOG --
libbpf: Error loading .BTF into kernel: -22. BTF is optional, ignoring.
libbpf: prog 'hello': BPF program load failed: Permission denied
libbpf: prog 'hello': -- BEGIN PROG LOAD LOG --
0: R1=ctx(off=0,imm=0) R10=fp0
0: (7b) *(u64 *)(r10 -8) = r1         ; R1=ctx(off=0,imm=0) R10=fp0 fp-8_w=ctx
1: (b7) r1 = 2                        ; R1_w=2
2: (7b) *(u64 *)(r10 -32) = r1        ; R1_w=2 R10=fp0 fp-32_w=2
3: (85) call pc+17
caller:
 R10=fp0 fp-8_w=ctx fp-32_w=2
callee:
 frame1: R1_w=2 R10=fp0
21: frame1:
21: (7b) *(u64 *)(r10 -16) = r1       ; frame1: R1_w=2 R10=fp0 fp-16_w=2
22: (18) r1 = 0xffffc13e009a4400      ; frame1: R1_w=map_value(off=1024,ks=4,vs=1036,imm=0)
24: (79) r1 = *(u64 *)(r1 +0)         ; frame1: R1_w=scalar()
25: (55) if r1 != 0x0 goto pc+3       ; frame1: R1_w=0
26: (05) goto pc+0
27: (85) call pc+42
caller:
 frame1: R10=fp0 fp-16=2
callee:
 frame2: R1=0 R10=fp0
70: frame2:
70: (18) r1 = 0xffffc13e009a4400      ; frame2: R1_w=map_value(off=1024,ks=4,vs=1036,imm=0)
72: (18) r2 = 0xffffc13e009a4000      ; frame2: R2_w=map_value(off=0,ks=4,vs=1036,imm=0)
74: (7b) *(u64 *)(r1 +0) = r2         ; frame2: R1_w=map_value(off=1024,ks=4,vs=1036,imm=0) R2_w=map_value(off=0,ks=4,vs=1036,imm=0)
75: (79) r3 = *(u64 *)(r1 +0)         ; frame2: R1_w=map_value(off=1024,ks=4,vs=1036,imm=0) R3_w=scalar()
76: (b7) r2 = 1000                    ; frame2: R2_w=1000
77: (7b) *(u64 *)(r3 +0) = r2
R3 invalid mem access 'scalar'
processed 16 insns (limit 1000000) max_states_per_insn 0 total_states 1 peak_states 1 mark_read 0
-- END PROG LOAD LOG --
libbpf: prog 'hello': failed to load: -13
libbpf: failed to load object 'hello.bpf.o'
Error: failed to load object file
```
</details>
