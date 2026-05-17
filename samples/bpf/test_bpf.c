#include <uapi/linux/bpf.h>
#include <linux/version.h>
#include <bpf/bpf_helpers.h>

SEC("perf_event")
int bpf_prog(struct pt_regs *ctx) {
	char buf[] = "hello world\n Test program\n";
	bpf_trace_printk(buf, sizeof(buf));
	return 0;
}

char _license[] SEC("license") = "GPL";
