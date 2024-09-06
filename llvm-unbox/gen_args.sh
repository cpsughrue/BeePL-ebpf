clang -O2 -c main.c -target bpf -g -o main.o -mllvm --debug-pass=Executions &> pass_args_ebpf
clang -O2 -c main.c -g -o main.o -mllvm --debug-pass=Executions &> pass_args_norm

