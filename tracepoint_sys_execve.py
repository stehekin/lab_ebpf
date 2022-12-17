from bcc import BPF, lib
import os, sys
from ctypes import *

bpf_text = ""
bpf_program = """

#include <linux/sched.h>
#include <linux/pid.h>

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct pid *pid = task->thread_pid;

    int level = pid->level;
    for (int l = 5; l >= 0; l--) {
        if (l > level) {
            continue;
        }
        struct upid *upid = &pid->numbers[l];
        bpf_trace_printk("comm:%s level: %d  pid: %d", task->comm, l, upid->nr);
    }
	return 0;
}
"""


bpf_text += bpf_program
bpf = BPF(text=bpf_text)
bpf.trace_print()
