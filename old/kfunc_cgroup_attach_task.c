#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/cgroup-defs.h>

KFUNC_PROBE(cgroup_attach_task, struct cgroup * dst_cgrp, struct task_struct *leader, bool threadgroup) {
    // unsigned int level = leader->thread_pid->level;
    // bpf_trace_printk("task pid", leader->thread_pid->numbers[level].nr); 
    return 0;
}