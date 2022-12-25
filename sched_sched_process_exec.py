from bcc import BPF, lib
import os, sys
from ctypes import *

bpf_program = open(__file__.replace(".py", ".c"))
bpf_text = bpf_program.read()
bpf_program.close()

bpf = BPF(text=bpf_text)
bpf.trace_print()