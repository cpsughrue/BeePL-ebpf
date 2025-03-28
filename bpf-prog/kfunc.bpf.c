#include </usr/src/kernels/5.14.0-503.31.1.el9_5.x86_64/vmlinux.h>
#include <bpf/bpf_helpers.h>

// #define __ksym __attribute__((section(".ksyms")))
extern struct task_struct *bpf_task_acquire(struct task_struct *p) __ksym;
extern void bpf_task_release(struct task_struct *p);

SEC("tp_btf/task_newtask")
int task_acquire_release_example(struct task_struct *task, u64 clone_flags)
{
    struct task_struct *acquired;

    acquired = bpf_task_acquire(task);
    if (acquired)
            bpf_task_release(acquired);

    return 0;
}

char _license[] SEC("license") = "GPL";
