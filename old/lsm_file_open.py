from bcc import BPF, lib
import os, sys
from ctypes import *

bpf_text = ""
lsm_program = """
#include <linux/fs.h>
#include <linux/sched.h>

#define MAX_DIR_DEPTH 128

LSM_PROBE(file_open, struct file *file, int retv) {
    struct inode *inode = file->f_inode;
	return 0;
}
"""


bpf_text += lsm_program
bpf = BPF(text=bpf_text)
bpf.trace_print()
