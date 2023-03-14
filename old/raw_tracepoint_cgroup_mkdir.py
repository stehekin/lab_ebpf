from bcc import BPF, lib
import os, sys
from ctypes import *

bpf_text = ""
bpf_program = """
#include <linux/cgroup.h>


RAW_TRACEPOINT_PROBE(cgroup_mkdir) {
    // https://github.com/torvalds/linux/blob/master/include/trace/events/cgroup.h#L54
    
    struct cgroup *cgrp = (struct cgroup *)ctx->args[0];
    const char *path = (const char *)ctx->args[1];
    const char *kname = (const char *)cgrp->kn->name;

    bpf_trace_printk("kname %s level %d", kname, cgrp->level);

	return 0;
}
"""


bpf_text += bpf_program
bpf = BPF(text=bpf_text)
bpf.trace_print()
