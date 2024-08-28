# Emulating `malloc` and `free` in eBPF   

The goal of `static_malloc` and `static_free` is to emulate dynamic memory allocation in eBPF programs. `static_malloc` and `static_free` are drop in replacements for `malloc` and `free`. Any eBPF program rejected solely due to its reliance on `malloc` and `free` can be corrected by replacing all instances of `malloc` with `static_malloc`, replacing all instances of `free` with `static_free`, and appending `#include "dynamic_memory.h"` to the top of the source file.

To use `static_malloc` and `static_free` follow these steps.

DISCLAIMER: The following steps have only been tested on single file eBPF programs.

### 1. Modify source files

The first step is to replace `malloc` with `static_malloc`, replace `free` with `static_free`, and append `#include "dynamic_memory.h"` to the top of the source file. To do so use `modify.sh` under the `modify` subdirectory and run:

```bash
./modify.sh /path/to/source/file
```

To demonstrate I created an example source file: `modify/tests/example.c`. To see how `modify.sh` changes the source file take a look at `example.c` then run `./modify.sh /tests/example.c`.

### 2. Compile

Compile the eBPF program as you would normally compile your eBPF programs.

NOTE: You can also compile `dynamic_memory.h` with native executables by providing `-Dnative_executable` to the compiler. This functionality was added to allow for testing `static_malloc` and `static_free` in userspace. Examples of an eBPF build and a native_executable build can be found in `Makefile`

### Implementation Notes

The eBPF verifier will accept the program if it is implemented using static arrays (e.g., `uint8_t memory_pool[POOL_SIZE]`) as its memory blocks. However, `pthread_mutex_lock` cannot be used to manage concurrency because it does not have associated type information in the kernel's BTF data (`libbpf: failed to find BTF for extern 'pthread_mutex_lock' [23] section: -2`). Instead we must rely on two key features provided by eBPF maps to combat race conditions. First, we use the `PERCPU` variant of `BPF_MAP_TYPE_ARRAY` to minimize contention. Second, we use a `bpf_spin_lock` to guarantee only one kernel thread has access to `memory_pool` and `alloc_metadata` at a time.

### Versions

Testing has occurred on
```text
[cpsughrue@desktop repos]$ uname -a
Linux desktop 5.14.0-427.13.1.el9_4.x86_64 #1 SMP PREEMPT_DYNAMIC Wed May 1 19:11:28 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux
```
