/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_LWFP_H
#define _UAPI_LINUX_LWFP_H

#define PERF_LWFP_MATCH_REG       BIT(0)
#define PERF_LWFP_KERNEL_SPACE    BIT(1)
#define PERF_LWFP_USER_SPACE      BIT(2)
#define PERF_LWFP_MATCH_FLAGS     BIT(3)
#define PERF_LWFP_MATCH_ENCLAVE   BIT(4)

#define X86_64_REG_MAX (16)
#define ARM64_REG_MAX  (32)

#if defined(__x86_64__)
#define MAX_REGISTER_MATCH_COUNT X86_64_REG_MAX

enum x86_64_reg_idx {
	X86_REG_RAX = 0,
	X86_REG_RBX,
	X86_REG_RCX,
	X86_REG_RDX,
	X86_REG_RSI,
	X86_REG_RDI,
	X86_REG_RBP,
	X86_REG_RSP,
	X86_REG_R8,
	X86_REG_R9,
	X86_REG_R10,
	X86_REG_R11,
	X86_REG_R12,
	X86_REG_R13,
	X86_REG_R14,
	X86_REG_R15,
	X86_64_REG_MAX
};

#elif defined(__aarch64__)
#define MAX_REGISTER_MATCH_COUNT ARM64_REG_MAX

enum arm64_reg_idx {
	ARM64_REG_X0 = 0,
	ARM64_REG_X1, ARM64_REG_X2, ARM64_REG_X3, ARM64_REG_X4,
	ARM64_REG_X5, ARM64_REG_X6, ARM64_REG_X7, ARM64_REG_X8,
	ARM64_REG_X9, ARM64_REG_X10, ARM64_REG_X11, ARM64_REG_X12,
	ARM64_REG_X13, ARM64_REG_X14, ARM64_REG_X15, ARM64_REG_X16,
	ARM64_REG_X17, ARM64_REG_X18, ARM64_REG_X19, ARM64_REG_X20,
	ARM64_REG_X21, ARM64_REG_X22, ARM64_REG_X23, ARM64_REG_X24,
	ARM64_REG_X25, ARM64_REG_X26, ARM64_REG_X27, ARM64_REG_X28,
	ARM64_REG_X29, /* Frame Pointer */
	ARM64_REG_X30, /* Link Register */
	ARM64_REG_SP,  /* Stack Pointer */
	ARM64_REG_MAX
};

#else
#define MAX_REGISTER_MATCH_COUNT 32 /* Architecture-agnostic maximum fallback */
#endif

#define LWFP_FLAG_IP_INC		(1ULL << 0)
#define LWFP_FLAG_SINGLE_STEP	(1ULL << 1)
#define LWFP_FLAG_GSREG 		(1ULL << 2)
#define LWFP_FLAG_FSREG   		(1ULL << 3)

struct perf_sgx_attr {
	__u64 enclave_base;
	__u64 ssa_size;
	__u32 tcs_count;
	__u32 reserved;
	__u64 tcs_bases[64];
};

enum lwfp_type {
	LWFP_TYPE_NORMAL   = 0,
	LWFP_TYPE_ENCLAVE  = 1, /*match only RIP && RBX*/
	LWFP_TYPE_EXTENDED = 2,
	LWFP_TYPE_SGX 	   = 3, /*match only RIP, internal SGX registers */
	LWFP_TYPE_VM       = 4,
};

struct perf_lwfp_attr {
	uint64_t context0;
	uint64_t context1;
	uint64_t flags;
	uint64_t match;
	uint64_t regs[MAX_REGISTER_MATCH_COUNT];
};


#endif /* _UAPI_LINUX_LWFP_H */
