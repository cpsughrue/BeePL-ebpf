Monorepo for everything related to writing eBPF programs in koka.

`ebpf-dynamic-memory`: code to emulate malloc and free in eBPF programs<br>
`llvm-unbox`: investigation into using llvm passes to unbox boxed types<br>
`unity`: A unit testing framework written in C by ThrowTheSwitch. Currently it is only used by `ebpf-dynamic-memory`. The submodule is checked out at the latest release v2.6.0 (860062d). I realized after the fact that it is not uncommon to use gtest, a more mainstream piece of software, to test C code. A low priority todo is test the viability of using gtest in this repo<br>
