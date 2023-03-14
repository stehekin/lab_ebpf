from bcc import BPF, lib
import os, sys
from ctypes import *

bpf_text = ""
lsm_program = """
#include <linux/fs.h>
#include <linux/sched.h>

#define MAX_DIR_DEPTH 128

LSM_PROBE(inode_getxattr, struct dentry *dentry, const char *name) {
    bpf_trace_printk("--->%s", name);
	return 0;
}
"""


bpf_text += lsm_program
bpf = BPF(text=bpf_text)
bpf.trace_print()
