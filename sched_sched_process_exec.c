
#include <linux/cred.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/mm_types.h>
#include <linux/nsproxy.h>
#include <linux/user_namespace.h>
#include <net/net_namespace.h>
#include <linux/cgroup-defs.h>
#include <linux/kernfs.h>


struct sched_process_exec_args {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    int filename;
    int pid;
    int old_pid;
};


static void show_namespace() {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();    
    // Check the namespaces:
    // readlink /proc/<PID>/ns/net
    // Net namespace.
    bpf_trace_printk("net namespace id: %u", task->nsproxy->net_ns->ns.inum);
    
    // User namespace is in a different place.
    bpf_trace_printk("user namespace id: %u", task->cred->user_ns->ns.inum);

    // How about this?
    bpf_trace_printk("user namespace id: %u", task->mm->user_ns->ns.inum);    
}

static void show_cgid() {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();    
    struct cgroup_subsys_state *css= task->cgroups->subsys[cpuset_cgrp_id];
    struct kernfs_node *kn = css->cgroup->kn;
    bpf_trace_printk("task name: %s", task->comm);
    bpf_trace_printk("cgroup level :%d id: %lu name: %s", css->cgroup->level, kn->id, kn->name);    
}

static void show_args(struct sched_process_exec_args *spea) {
    bpf_trace_printk("filename--->%s  %d",  ((u64)spea + (u64)(spea->filename & 0xFFFF)), spea->pid);

    // Show args.
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct mm_struct *mm;
    bpf_probe_read(&mm, sizeof(mm), &task->mm);
    
    unsigned long arg_start, arg_end;
    bpf_probe_read(&arg_start, sizeof(arg_start), &mm->arg_start);
    bpf_probe_read(&arg_end, sizeof(arg_end), &mm->arg_end);

    bpf_trace_printk("first args (filename)->%s", (char *)arg_start);
}

TRACEPOINT_PROBE(sched, sched_process_exec) {
    // /sys/kernel/debug/tracing/events/sched/sched_process_exec/format    
    // https://github.com/iovisor/bpftrace/issues/999
    // https://github.com/iovisor/bpftrace/issues/385
    
    struct sched_process_exec_args *spea = (struct sched_process_exec_args *)args;
    // show_args(spea);
    // show_namespace();
    show_cgid();
    return 0;
}