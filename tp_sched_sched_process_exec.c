#include <linux/sched.h>
#include <linux/cgroup-defs.h>
#include <linux/kernfs.h>

TRACEPOINT_PROBE(cgroup, cgroup_attach_task) {
    bpf_trace_printk("attach %u to cgroup %d with root %d", args->pid, args->dst_id, args->dst_root);
    return 0;
}

TRACEPOINT_PROBE(sched, sched_process_exec) {
    /*, char *filename, pid_t pid, pid_t old_pid*/
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct cgroup *cgroup = task->cgroups->dfl_cgrp;
    bpf_trace_printk("process :%d cgroup: %d name: %s", task->pid, cgroup->kn->id, cgroup->kn->name);
    return 0;
}
