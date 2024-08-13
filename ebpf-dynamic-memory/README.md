# Emulating `malloc` and `free` in eBPF   

The goal of `static_malloc` and `static_free` is to emulate dynamic memory allocation in eBPF programs. `static_malloc` and `static_free` are drop in replacements for `malloc` and `free`. Any eBPF program rejected solely due to its reliance on `malloc` and `free` can be corrected by replacing all instances of `malloc` with `static_malloc`, replacing all instances of `free` with `static_free`, and appending `#include "dynamic_memory.h"` to the top of the source file.

To use `static_malloc` and `static_free` follow these steps.

DISCLAIMER: The following steps have only been tested on single file eBPF programs. I am currently working on adapting everything to also be compatible with multi-file eBPF programs. 

### 1. Modify source files

The first step is to replace `malloc` with `static_malloc`, replace `free` with `static_free`, and append `dynamic_memory.h` to the top of the source file. To do so use `modify.sh` under the `modify` subdirectory and run:

```bash
./modify.sh /path/to/c/source/file
```

To demonstrate I created an example source file: `modify/tests/example.c`. To see how `modify.sh` changes the source file take a look at `example.c` then run `./modify.sh /tests/example.c`.

### 2. Compile

Compile the eBPF program as you would normally compile your eBPF programs.

NOTE: You can also compile `dynamic_memory.h` with native executables by providing `-Dnative_executable` to the compiler. This functionality was added to allow for testing `static_malloc` and `static_free` in userspace. Examples, of an eBPF build and a native_executable build can be found in `Makefile`
