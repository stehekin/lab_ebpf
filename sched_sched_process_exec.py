from bcc import BPF, lib
import os, sys
from ctypes import *

bpf_text = ""
bpf_program = """

#include <linux/types.h>
#include <linux/sched.h>

struct sched_process_exec_args {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	int filename;
	int pid;
	int old_pid;
};

TRACEPOINT_PROBE(sched, sched_process_exec) {
    // /sys/kernel/debug/tracing/events/sched/sched_process_exec/format
	
    // https://github.com/iovisor/bpftrace/issues/999
    // https://github.com/iovisor/bpftrace/issues/385
    struct sched_process_exec_args *spea = (struct sched_process_exec_args *)args;
    bpf_trace_printk("filename--->%s  %d",  ((u64)args + (u64)(spea->filename & 0xFFFF)), spea->pid);
    return 0;
}
"""


bpf_text += bpf_program
bpf = BPF(text=bpf_text)
bpf.trace_print()
