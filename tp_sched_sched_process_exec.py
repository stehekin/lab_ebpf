from bcc import BPF, lib

bpf = BPF(src_file=__file__.replace(".py", ".c"))
bpf.trace_print()