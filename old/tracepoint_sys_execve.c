#include <linux/sched.h>
#include <linux/pid.h>

static void display_pids(struct task_struct *task) {
    struct pid *pid = task->thread_pid;
    int level = pid->level;

    for (int l = 5; l >= 0; l--) {
        if (l > level) {
            continue;
        }
        struct upid *upid = &pid->numbers[l];
        bpf_trace_printk("comm:%s level: %d  pid: %d", task->comm, l, upid->nr);
    }
}

static void display_user_namespace(struct task_struct *task) {

}

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    display_pids(task);
    return 0;
}