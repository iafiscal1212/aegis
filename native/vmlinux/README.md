## vmlinux headers

These are pre-generated BTF headers for eBPF compilation.

### Generate for your system

```bash
# x86_64
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux_x86_64.h

# aarch64
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux_aarch64.h
```

### Download pre-built

From https://github.com/libbpf/libbpf-bootstrap/tree/master/vmlinux
