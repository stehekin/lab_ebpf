from bcc import BPF, lib
import os, sys
from ctypes import *

bpf_text = ""
lsm_program = """
#include <linux/fs.h>
#include <linux/sched.h>

RAW_TRACEPOINT_PROBE(cgroup_mkdir) {
	return 0;
}
"""


bpf_text += lsm_program
bpf = BPF(text=bpf_text)
bpf.trace_print()
