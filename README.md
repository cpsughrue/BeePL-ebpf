Monorepo for everything related to writing eBPF programs in koka.

* `ebpf-dynamic-memory`: code to emulate malloc and free in eBPF programs<br>
* `llvm-unbox`: investigation into using llvm passes to unbox boxed types<br>
* `unity`: A unit testing framework written in C by ThrowTheSwitch. The submodule is checked out at the latest release v2.6.0 (860062d). I realized after the fact that it is not uncommon to use gtest, a unittesting framework written in C++, to test C code. A low priority todo is test the viability of using gtest in this repo<br>


clang -target bpf -Wall -Wextra -I/usr/include/x86_64-linux-gnu -g -O2 -c -o packet_count.bpf.o packet_count.bpf.c

sudo /usr/local/sbin/bpftool prog load packet_count.bpf.o /sys/fs/bpf/packet_count

