// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2007 Alan Stern
 * Copyright (C) IBM Corporation, 2009
 * Copyright (C) 2009, Frederic Weisbecker <fweisbec@gmail.com>
 *
 * Thanks to Ingo Molnar for his many suggestions.
 *
 * Authors: Alan Stern <stern@rowland.harvard.edu>
 *          K.Prasad <prasad@linux.vnet.ibm.com>
 *          Frederic Weisbecker <fweisbec@gmail.com>
 */

/*
 * HW_breakpoint: a unified kernel/user-space hardware breakpoint facility,
 * using the CPU's debug registers.
 * This file contains the arch-independent routines.
 */

#include <linux/irqflags.h>
#include <linux/kallsyms.h>
#include <linux/notifier.h>
#include <linux/kprobes.h>
#include <linux/kdebug.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/percpu.h>
#include <linux/sched.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/hashtable.h>
#include <linux/bitops.h>
#include <linux/cpu.h>
#include <linux/smp.h>
#include <linux/bug.h>
#include <linux/refcount.h>
#include <linux/rcupdate.h>
#include <linux/uaccess.h>
#include <linux/atomic.h>
#include <linux/mm.h>
#include <linux/mmap_lock.h>

#include <asm/ptrace.h>
#include <linux/kvm_host.h>
#include <uapi/linux/lwfp.h>
#include <linux/perf_event.h>

#define EVENT_HTABLE_WIDTH	16
#define LWFP_MODULE_WIDTH	4
#define PROC_TABLE_WIDTH	4

#if defined(__x86_64__)
static const int arch_reg_offsets[MAX_REGISTER_MATCH_COUNT] = {
	[X86_REG_RAX] = offsetof(struct pt_regs, ax),
	[X86_REG_RBX] = offsetof(struct pt_regs, bx),
	[X86_REG_RCX] = offsetof(struct pt_regs, cx),
	[X86_REG_RDX] = offsetof(struct pt_regs, dx),
	[X86_REG_RSI] = offsetof(struct pt_regs, si),
	[X86_REG_RDI] = offsetof(struct pt_regs, di),
	[X86_REG_RBP] = offsetof(struct pt_regs, bp),
	[X86_REG_RSP] = offsetof(struct pt_regs, sp),
	[X86_REG_R8]  = offsetof(struct pt_regs, r8),
	[X86_REG_R9]  = offsetof(struct pt_regs, r9),
	[X86_REG_R10] = offsetof(struct pt_regs, r10),
	[X86_REG_R11] = offsetof(struct pt_regs, r11),
	[X86_REG_R12] = offsetof(struct pt_regs, r12),
	[X86_REG_R13] = offsetof(struct pt_regs, r13),
	[X86_REG_R14] = offsetof(struct pt_regs, r14),
	[X86_REG_R15] = offsetof(struct pt_regs, r15),
};
#elif defined(__aarch64__)
static const int arch_reg_offsets[MAX_REGISTER_MATCH_COUNT] = {
	[ARM64_REG_X0]  = offsetof(struct pt_regs, regs[0]),
	[ARM64_REG_X1]  = offsetof(struct pt_regs, regs[1]),
	[ARM64_REG_X2]  = offsetof(struct pt_regs, regs[2]),
	[ARM64_REG_X3]  = offsetof(struct pt_regs, regs[3]),
	[ARM64_REG_X4]  = offsetof(struct pt_regs, regs[4]),
	[ARM64_REG_X5]  = offsetof(struct pt_regs, regs[5]),
	[ARM64_REG_X6]  = offsetof(struct pt_regs, regs[6]),
	[ARM64_REG_X7]  = offsetof(struct pt_regs, regs[7]),
	[ARM64_REG_X8]  = offsetof(struct pt_regs, regs[8]),
	[ARM64_REG_X9]  = offsetof(struct pt_regs, regs[9]),
	[ARM64_REG_X10] = offsetof(struct pt_regs, regs[10]),
	[ARM64_REG_X11] = offsetof(struct pt_regs, regs[11]),
	[ARM64_REG_X12] = offsetof(struct pt_regs, regs[12]),
	[ARM64_REG_X13] = offsetof(struct pt_regs, regs[13]),
	[ARM64_REG_X14] = offsetof(struct pt_regs, regs[14]),
	[ARM64_REG_X15] = offsetof(struct pt_regs, regs[15]),
	[ARM64_REG_X16] = offsetof(struct pt_regs, regs[16]),
	[ARM64_REG_X17] = offsetof(struct pt_regs, regs[17]),
	[ARM64_REG_X18] = offsetof(struct pt_regs, regs[18]),
	[ARM64_REG_X19] = offsetof(struct pt_regs, regs[19]),
	[ARM64_REG_X20] = offsetof(struct pt_regs, regs[20]),
	[ARM64_REG_X21] = offsetof(struct pt_regs, regs[21]),
	[ARM64_REG_X22] = offsetof(struct pt_regs, regs[22]),
	[ARM64_REG_X23] = offsetof(struct pt_regs, regs[23]),
	[ARM64_REG_X24] = offsetof(struct pt_regs, regs[24]),
	[ARM64_REG_X25] = offsetof(struct pt_regs, regs[25]),
	[ARM64_REG_X26] = offsetof(struct pt_regs, regs[26]),
	[ARM64_REG_X27] = offsetof(struct pt_regs, regs[27]),
	[ARM64_REG_X28] = offsetof(struct pt_regs, regs[28]),
	[ARM64_REG_X29] = offsetof(struct pt_regs, regs[29]),
	[ARM64_REG_X30] = offsetof(struct pt_regs, regs[30]),
	[ARM64_REG_SP]  = offsetof(struct pt_regs, sp),
};
#endif

/*
 * SGX GPRSGX layout (Intel SDM, SSA GPRSGX area). 184 bytes.
 */
struct gprs {
	u64 rax;
	u64 rcx;
	u64 rdx;
	u64 rbx;
	u64 rsp;
	u64 rbp;
	u64 rsi;
	u64 rdi;
	u64 r8;
	u64 r9;
	u64 r10;
	u64 r11;
	u64 r12;
	u64 r13;
	u64 r14;
	u64 r15;
	u64 rflags;
	u64 rip;
	u64 ursp;
	u64 urbp;
	u32 exitinfo;
	u8 reserved[3];
	u8 aexnotify;
	u64 fsbase;
	u64 gsbase;
} __packed;

typedef struct gprs gprs_t;

static_assert(sizeof(gprs_t) == 184, "gprs_t must match SGX GPRSGX layout");

#define SGX_GPRSGX_RFLAGS_OFFSET	offsetof(gprs_t, rflags)
#define SGX_GPRSGX_RIP_OFFSET		offsetof(gprs_t, rip)

struct lwfp {
	u64 base_addr;
	struct perf_event *event;
	u64 config1;
	u64 config2;
	pid_t o_pid;
	pid_t t_pid;
	pid_t t_tid;
	enum lwfp_type type;
	struct perf_lwfp_attr *attr;

	/* SGX-specific storage: kernel-owned copy of user data. */
	struct perf_sgx_attr *sgx_attr;
	size_t sgx_attr_size;

	struct list_head node;
	struct rcu_head rcu;
	bool removed;
	refcount_t refs;
};

struct thread_node {
	pid_t tid;
	struct list_head lwfp_list;
	struct hlist_node node;
	spinlock_t lwfp_lock;
	struct rcu_head rcu;
	refcount_t refcount;
};

struct process_node {
	pid_t pid;
	struct hlist_node node;
	DECLARE_HASHTABLE(thread_hashtable, PROC_TABLE_WIDTH);
	spinlock_t thread_lock;
	struct rcu_head rcu;
	refcount_t refcount;
};

struct lwfp_event {
	struct perf_event *event;
	struct lwfp *value;
	struct hlist_node node;
	struct rcu_head rcu;
	refcount_t refs;
};

struct lwfp_context {
	struct perf_lwfp_attr *lwfp_attr;
	struct perf_event *event;
	struct pt_regs *regs;
};

struct lwfp_sgx_match_state {
	gprs_t gprs;
	u64 gprsgx_addr;
	bool gprs_valid;
	struct pt_regs regs;
};

DEFINE_HASHTABLE(lwfp_module, LWFP_MODULE_WIDTH);
DEFINE_HASHTABLE(events_table, EVENT_HTABLE_WIDTH);

static spinlock_t lwfp_module_lock;
static spinlock_t events_lock;

#if defined(CONFIG_HAVE_KVM)
/*TODO: Fix the architecture dependent writes*/

typedef int (*lwfp_kvm_nmi_handler_t)(struct kvm_vcpu *vcpu);

extern void *kvm_switch_handle_exception_nmi(void *new_handler);

static int lwfp_handle_kvm_exception_nmi(struct kvm_vcpu *vcpu);


static int lwfp_default_kvm_handle_exception_nmi(struct kvm_vcpu *vcpu)
{
	(void)vcpu;

	return 0;
}

static atomic_long_t kvm_handle_exception_nmi =
	ATOMIC_LONG_INIT((long)lwfp_default_kvm_handle_exception_nmi);

/*
 * This is the handler returned by KVM when the local LWFP handler
 * is installed. It is passed back to KVM during restoration.
 */
static void *kvm_original_handle_exception_nmi;

#endif /* CONFIG_KVM */

static struct lwfp *search_for_event(pid_t pid, pid_t tid,
				     struct pt_regs *regs,
				     struct lwfp_sgx_match_state *sgx_state);
static int execute_event(struct lwfp *target, struct pt_regs *regs,
			struct lwfp_sgx_match_state *sgx_state);

static void lwfp_rcu_free(struct rcu_head *rcu)
{
	struct lwfp *lwfp;

	lwfp = container_of(rcu, struct lwfp, rcu);
	kfree(lwfp->sgx_attr);
	kfree(lwfp->attr);
	kfree(lwfp);
}

static void lwfp_put(struct lwfp *lwfp)
{
	if (lwfp && refcount_dec_and_test(&lwfp->refs))
		call_rcu(&lwfp->rcu, lwfp_rcu_free);
}

static void thread_node_rcu_free(struct rcu_head *rcu)
{
	struct thread_node *thread;

	thread = container_of(rcu, struct thread_node, rcu);
	kfree(thread);
}

static void thread_node_put(struct thread_node *thread)
{
	if (thread && refcount_dec_and_test(&thread->refcount))
		call_rcu(&thread->rcu, thread_node_rcu_free);
}

static void process_node_rcu_free(struct rcu_head *rcu)
{
	struct process_node *proc;

	proc = container_of(rcu, struct process_node, rcu);
	kfree(proc);
}

static void process_node_put(struct process_node *proc)
{
	if (proc && refcount_dec_and_test(&proc->refcount))
		call_rcu(&proc->rcu, process_node_rcu_free);
}

static void lwfp_event_rcu_free(struct rcu_head *rcu)
{
	struct lwfp_event *event;

	event = container_of(rcu, struct lwfp_event, rcu);
	kfree(event);
}

static void lwfp_event_put(struct lwfp_event *event)
{
	if (event && refcount_dec_and_test(&event->refs))
		call_rcu(&event->rcu, lwfp_event_rcu_free);
}

static inline int
lwfp_match_regs_attr(const struct perf_lwfp_attr *attr,
		     const struct pt_regs *regs)
{
	unsigned long match_bitmap;
	unsigned int bit_index;
	u64 reg_value;
	int count = 0;

	if (!attr || !regs)
		return 0;

	match_bitmap = (unsigned long)attr->match;
	if (!match_bitmap)
		return 0;

	for_each_set_bit(bit_index, &match_bitmap,
			 MAX_REGISTER_MATCH_COUNT) {
#if defined(__x86_64__) || defined(__aarch64__)
		reg_value = regs_get_register((struct pt_regs *)regs,
					      arch_reg_offsets[bit_index]);
#else
		reg_value = 0;
#endif
		if (reg_value != attr->regs[bit_index])
			return 0;

		count++;
	}

	return count > 0;
}

static int lwfp_extended_handle_flags(struct lwfp *lwfp,
				      struct pt_regs *regs)
{
	u64 flags;

	if (!lwfp || !lwfp->attr || !regs)
		return -EINVAL;

	flags = lwfp->attr->flags;

	if (flags & LWFP_FLAG_IP_INC)
		instruction_pointer_set(regs,
					instruction_pointer(regs) + 1);

#if defined(CONFIG_X86_64)
	if (flags & LWFP_FLAG_SINGLE_STEP)
		regs->flags |= X86_EFLAGS_TF;
#elif defined(CONFIG_ARM64)
	if (flags & LWFP_FLAG_SINGLE_STEP)
		regs->pstate |= PSR_D_BIT;
#endif

	return 0;
}

#if defined(CONFIG_ARM64)
void kvm_set_vcpu_ip(struct kvm_vcpu *vcpu, unsigned long new_pc) {
    vcpu_gp_regs(vcpu)->pc = new_pc;

    smp_wmb();
    set_bit(KVM_REQ_EVENT & KVM_REQUEST_MASK, (unsigned long *)&vcpu->requests);
}
#endif

static int lwfp_kvm_handle_flags(struct lwfp *lwfp,
				 struct kvm_vcpu *vcpu,
				 struct pt_regs *regs)
{
	u64 flags;
	unsigned long ip;

	if (!lwfp || !lwfp->attr || !vcpu || !regs)
		return -EINVAL;

	flags = lwfp->attr->flags;

	if (flags & LWFP_FLAG_IP_INC) {
		ip = instruction_pointer(regs) + 1;
		instruction_pointer_set(regs, ip);

#if defined(CONFIG_X86_64)
		vcpu->arch.regs[VCPU_REGS_RIP] = ip;
		__clear_bit(VCPU_REGS_RIP, (unsigned long *)&vcpu->arch.regs_avail);
		__clear_bit(VCPU_REGS_RIP, (unsigned long *)&vcpu->arch.regs_dirty);
#elif defined(CONFIG_ARM64)
		kvm_set_vcpu_ip(vcpu, ip);
#else
		return -EOPNOTSUPP;
#endif
	}

	if (flags & LWFP_FLAG_SINGLE_STEP) {
		vcpu->guest_debug |=
			KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_SINGLESTEP;
	}

	return 0;
}

/*
 * Validate that [addr, addr + len) is:
 *   - a userspace range (access_ok())
 *   - fully contained within a single VMA belonging to task->mm
 *
 * This must be called before any read/write into enclave memory,
 * since gprsgx_addr is derived from user-controlled enclave_base,
 * ssa_framesize, and TCS values.
 */
static int lwfp_sgx_validate_user_range(struct task_struct *task,
					unsigned long addr,
					size_t len)
{
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	int ret = -EFAULT;

	if (!task || !task->mm || !len)
		return -EINVAL;

	if (addr + len < addr)
		return -EOVERFLOW;

	if (!access_ok((void __user *)addr, len))
		return -EFAULT;

	mm = task->mm;

	mmap_read_lock(mm);

	vma = find_vma(mm, addr);
	if (!vma || vma->vm_start > addr)
		goto out_unlock;

	if (addr + len > vma->vm_end)
		goto out_unlock;

	/*
	 * The enclave mapping must not be writable/executable from the
	 * kernel's point of view in ways that indicate it isn't the
	 * expected SGX enclave VMA. At minimum, require that it is a
	 * valid, non-special mapping.
	 */
	if (vma->vm_flags & VM_SPECIAL)
		goto out_unlock;

	ret = 0;

out_unlock:
	mmap_read_unlock(mm);

	return ret;
}

/*
 * Compute the GPRSGX address for a given TCS within the enclave,
 * validating that the resulting address range lies within the
 * task's enclave VMA before returning it.
 */
static void *
lwfp_sgx_get_gprsgx_addr(struct task_struct *task,
			 u64 enclave_base,
			 u64 tcs_addr,
			 u32 ssa_framesize)
{
	u64 gprsgx_addr;
	int ret;

	if (!task || !enclave_base || !tcs_addr || !ssa_framesize)
		return NULL;

	/*
	 * The exact SSA/GPRSGX offset calculation depends on the SGX
	 * layout used by this driver's enclave loader (SSA frame index,
	 * XSAVE area size, etc). ssa_framesize here represents the fixed
	 * per-SSA-frame size preceding the GPRSGX region.
	 */
	if (check_add_overflow(tcs_addr, (u64)ssa_framesize, &gprsgx_addr))
		return NULL;

	ret = lwfp_sgx_validate_user_range(task,
					   (unsigned long)gprsgx_addr,
					   sizeof(gprs_t));
	if (ret)
		return NULL;

	return (void *)(unsigned long)gprsgx_addr;
}

/*
 * Read or write the GPRSGX area for a remote task, after validating
 * that [addr, addr + len) is a userspace range fully contained in
 * the task's mm.
 */
static int lwfp_sgx_access_enclave(struct task_struct *task,
				   unsigned long addr,
				   void *buf,
				   size_t len,
				   bool write)
{
	int ret;
	int access_ret;

	if (!task || !task->mm || !addr || !buf || !len)
		return -EINVAL;

	ret = lwfp_sgx_validate_user_range(task, addr, len);
	if (ret)
		return ret;

	access_ret = access_process_vm(task,
				       addr,
				       buf,
				       len,
				       write ? FOLL_WRITE : 0);
	if (access_ret != len)
		return -EFAULT;

	return 0;
}

static int lwfp_sgx_handle_flags(struct lwfp *lwfp,
				 struct task_struct *task,
				 u64 gprsgx_addr,
				 struct pt_regs *regs)
{
	u64 value;
	int ret;

	if (!lwfp || !lwfp->attr || !task || !gprsgx_addr || !regs)
		return -EINVAL;

	if (lwfp->attr->flags & LWFP_FLAG_IP_INC) {
		value = instruction_pointer(regs) + 1;

		ret = lwfp_sgx_access_enclave(
			task,
			gprsgx_addr + SGX_GPRSGX_RIP_OFFSET,
			&value,
			sizeof(value),
			true);
		if (ret)
			return ret;

		instruction_pointer_set(regs, value);
	}

	if (lwfp->attr->flags & LWFP_FLAG_SINGLE_STEP) {
		value = regs->flags | X86_EFLAGS_TF;

		ret = lwfp_sgx_access_enclave(
			task,
			gprsgx_addr + SGX_GPRSGX_RFLAGS_OFFSET,
			&value,
			sizeof(value),
			true);
		if (ret)
			return ret;

		regs->flags = value;
	}

	return 0;
}

static int
lwfp_handle_flags(struct lwfp *lwfp,
		  struct pt_regs *regs,
		  struct kvm_vcpu *vcpu,
		  struct task_struct *task,
		  u64 gprsgx_addr)
{
	if (!lwfp || !lwfp->attr || !lwfp->attr->flags)
		return 0;

	switch (lwfp->type) {
	case LWFP_TYPE_EXTENDED:
		return lwfp_extended_handle_flags(lwfp, regs);

	case LWFP_TYPE_VM:
		return lwfp_kvm_handle_flags(lwfp, vcpu, regs);

	case LWFP_TYPE_SGX:
		return lwfp_sgx_handle_flags(lwfp, task, gprsgx_addr, regs);

	default:
		return 0;
	}
}

static bool unlink_empty_process(struct process_node *proc)
{
	bool removed = false;

	if (!proc)
		return false;

	spin_lock(&proc->thread_lock);

	if (hash_empty(proc->thread_hashtable)) {
		spin_lock(&lwfp_module_lock);

		if (!hlist_unhashed(&proc->node)) {
			hash_del_rcu(&proc->node);
			removed = true;
		}
		spin_unlock(&lwfp_module_lock);
	}

	spin_unlock(&proc->thread_lock);

	return removed;
}


static int execute_event(struct lwfp *target,
			struct pt_regs *regs,
			struct lwfp_sgx_match_state *sgx_state)
{

	if (!target || !target->event || !regs)
		return 0;

	switch (target->type) {
	case LWFP_TYPE_NORMAL:
	case LWFP_TYPE_ENCLAVE:
		perf_bp_event(target->event, regs);
		return 0;
	case LWFP_TYPE_EXTENDED:
		perf_bp_event(target->event, regs);
		return lwfp_handle_flags(target, regs, NULL, NULL, 0);

	case LWFP_TYPE_SGX:
		if (!sgx_state || !sgx_state->gprs_valid)
			return -EFAULT;

		perf_bp_event(target->event, &sgx_state->regs);
		return lwfp_sgx_handle_flags(target,
					     current,
					     sgx_state->gprsgx_addr,
					     &sgx_state->regs);

	case LWFP_TYPE_VM:
		pr_err_ratelimited(
			"lwfp: unexpected LWFP_TYPE_VM in INT3 notifier; "
			"VM breakpoints must be handled by the KVM exception/NMI path\n");
		return -EOPNOTSUPP;

	default:
		return 0;
	}
}

int lwfp_exceptions_notify(struct notifier_block *unused,
			   unsigned long val,
			   void *data)
{
	struct die_args *args = data;
	struct lwfp_sgx_match_state sgx_state = {};
	struct pt_regs *regs;
	struct lwfp *lwfp;
	int ret;

	sgx_state.gprs_valid = 0;

	if (val != DIE_INT3)
		return NOTIFY_DONE;

	if (!args || !args->regs)
		return NOTIFY_DONE;

	regs = args->regs;

	if (!user_mode(regs))
		return NOTIFY_DONE;

	lwfp = search_for_event(task_tgid_nr(current),
				task_pid_nr(current),
				regs,
				&sgx_state);
	if (!lwfp)
		return NOTIFY_DONE;

	ret = execute_event(lwfp, regs, &sgx_state);

	lwfp_put(lwfp);

	if (ret < 0)
		return NOTIFY_DONE;

	return ret ? NOTIFY_STOP : NOTIFY_DONE;
}

static struct notifier_block lwfp_exceptions_nb = {
	.notifier_call = lwfp_exceptions_notify,
	.priority = 0x7fffffff,
};

static int remove_and_free_lwfp(struct thread_node *thread,
				struct lwfp *bp)
{
	bool removed = false;

	if (!bp || !thread)
		return 0;

	spin_lock(&thread->lwfp_lock);

	if (!bp->removed) {
		bp->removed = true;
		list_del_rcu(&bp->node);
		removed = true;
	}

	spin_unlock(&thread->lwfp_lock);

	if (removed)
		lwfp_put(bp);

	return removed;
}

static int remove_thread(struct process_node *proc,
			 struct thread_node *thread)
{
	bool removed = false;

	if (!proc || !thread)
		return 0;

	spin_lock(&proc->thread_lock);

	if (!hlist_unhashed(&thread->node)) {
		hash_del_rcu(&thread->node);
		removed = true;
	}

	spin_unlock(&proc->thread_lock);

	if (removed)
		thread_node_put(thread);

	return removed;
}

static struct thread_node *
lwfp_get_thread_node(struct process_node *proc, pid_t tid)
{
	struct thread_node *thread;

	if (!proc)
		return NULL;

	rcu_read_lock();

	hash_for_each_possible_rcu(proc->thread_hashtable,
				   thread,
				   node,
				   tid) {
		if (thread->tid == tid &&
		    refcount_inc_not_zero(&thread->refcount)) {
			rcu_read_unlock();
			return thread;
		}
	}

	rcu_read_unlock();

	return NULL;
}

static struct process_node *
lwfp_get_process_node(pid_t pid)
{
	struct process_node *proc;

	rcu_read_lock();

	hash_for_each_possible_rcu(lwfp_module, proc, node, pid) {
		if (proc->pid == pid &&
		    refcount_inc_not_zero(&proc->refcount)) {
			rcu_read_unlock();
			return proc;
		}
	}

	rcu_read_unlock();

	return NULL;
}

static int remove_process(pid_t pid)
{
	struct process_node *proc;
	bool empty;
	bool removed = false;

	proc = lwfp_get_process_node(pid);
	if (!proc)
		return 0;

	spin_lock(&proc->thread_lock);
	empty = hash_empty(proc->thread_hashtable);
	spin_unlock(&proc->thread_lock);

	if (!empty) {
		process_node_put(proc);
		return 0;
	}

	spin_lock(&lwfp_module_lock);

	if (!hlist_unhashed(&proc->node)) {
		hash_del_rcu(&proc->node);
		removed = true;
	}

	spin_unlock(&lwfp_module_lock);

	process_node_put(proc);

	if (removed)
		process_node_put(proc);

	return removed;
}

/*TODO: This is unused*/
static struct thread_node *
add_new_thread(struct process_node *node, pid_t tid)
{
	struct thread_node *new_thread;

	new_thread = kzalloc(sizeof(*new_thread), GFP_KERNEL);
	if (!new_thread)
		return NULL;

	new_thread->tid = tid;
	INIT_LIST_HEAD(&new_thread->lwfp_list);
	spin_lock_init(&new_thread->lwfp_lock);
	refcount_set(&new_thread->refcount, 1);

	spin_lock(&node->thread_lock);
	hash_add_rcu(node->thread_hashtable, &new_thread->node, tid);
	spin_unlock(&node->thread_lock);

	return new_thread;
}

/*TODO: This is unused*/
static struct process_node *
add_new_process(pid_t pid)
{
	struct process_node *new_node;

	new_node = kzalloc(sizeof(*new_node), GFP_KERNEL);
	if (!new_node)
		return NULL;

	new_node->pid = pid;
	spin_lock_init(&new_node->thread_lock);
	hash_init(new_node->thread_hashtable);
	refcount_set(&new_node->refcount, 1);

	spin_lock(&lwfp_module_lock);
	hash_add_rcu(lwfp_module, &new_node->node, pid);
	spin_unlock(&lwfp_module_lock);

	return new_node;
}

/*
 * Validate the SGX attribute structure referenced by
 * attr->context1.
 */
static int validate_sgx_lwfp_attr(const struct perf_lwfp_attr *attr,
				  size_t *sgx_size)
{
	struct perf_sgx_attr header;
	void __user *user_sgx;
	size_t tcs_bytes;

	if (!attr || !attr->context1 || !sgx_size)
		return -EINVAL;

	user_sgx = u64_to_user_ptr(attr->context1);

	if (copy_from_user(&header, user_sgx, sizeof(header)))
		return -EFAULT;

	if (!header.ssa_framesize || !header.tcs_count)
		return -EINVAL;

	if (header.tcs_count > ARRAY_SIZE(header.tcs_bases))
		return -EINVAL;

	*sgx_size = sizeof(header);

	return 0;
}

/*
 * Allocate and populate a partial lwfp for an SGX probe: copies
 * perf_lwfp_attr from event_attr->config2, validates the referenced
 * perf_sgx_attr, and copies the complete SGX structure into
 * kernel-owned memory. Common lwfp fields are filled in by the
 * caller (add_new_lwfp()).
 */
static struct lwfp *
handle_sgx_lwfp(const struct perf_event_attr *event_attr)
{
	struct perf_lwfp_attr *lwfp_attr;
	struct perf_sgx_attr *sgx_attr;
	struct lwfp *lwfp;
	void __user *user_attr;
	void __user *user_sgx;
	size_t sgx_size;
	int ret;

	if (!event_attr || !event_attr->config2)
		return ERR_PTR(-EINVAL);

	user_attr = u64_to_user_ptr(event_attr->config2);

	lwfp_attr = kzalloc(sizeof(*lwfp_attr), GFP_KERNEL);
	if (!lwfp_attr)
		return ERR_PTR(-ENOMEM);

	if (copy_from_user(lwfp_attr,
			   user_attr,
			   sizeof(*lwfp_attr))) {
		ret = -EFAULT;
		goto err_attr;
	}

	ret = validate_sgx_lwfp_attr(lwfp_attr, &sgx_size);
	if (ret)
		goto err_attr;

	user_sgx = u64_to_user_ptr(lwfp_attr->context1);

	sgx_attr = kmalloc(sgx_size, GFP_KERNEL);
	if (!sgx_attr) {
		ret = -ENOMEM;
		goto err_attr;
	}

	if (copy_from_user(sgx_attr, user_sgx, sgx_size)) {
		ret = -EFAULT;
		goto err_sgx;
	}

	lwfp = kzalloc(sizeof(*lwfp), GFP_KERNEL);
	if (!lwfp) {
		ret = -ENOMEM;
		goto err_sgx;
	}

	lwfp->attr = lwfp_attr;
	lwfp->sgx_attr = sgx_attr;
	lwfp->sgx_attr_size = sgx_size;

	return lwfp;

err_sgx:
	kfree(sgx_attr);
err_attr:
	kfree(lwfp_attr);

	return ERR_PTR(ret);
}

static struct lwfp *
add_new_lwfp(struct perf_event *event,
	     struct thread_node *target)
{
	struct lwfp *lwfp;
	unsigned long count;

	if (event->attr.bp_type == LWFP_TYPE_SGX) {
		lwfp = handle_sgx_lwfp(&event->attr);
		if (IS_ERR(lwfp))
			return NULL;
	} else {
		lwfp = kzalloc(sizeof(*lwfp), GFP_KERNEL);
		if (!lwfp)
			return NULL;

		if (event->attr.bp_type == LWFP_TYPE_VM ||
		    event->attr.bp_type == LWFP_TYPE_EXTENDED) {
			if (!event->attr.config2)
				goto error_attr_alloc;

			lwfp->attr = kzalloc(sizeof(*lwfp->attr),
					     GFP_KERNEL);
			if (!lwfp->attr)
				goto error_attr_alloc;

			count = copy_from_user(
				lwfp->attr,
				u64_to_user_ptr(event->attr.config2),
				sizeof(*lwfp->attr));
			if (count != 0)
				goto error_copy;
		}
	}

	lwfp->config1 = event->attr.config1;
	lwfp->config2 = event->attr.config2;
	lwfp->type = event->attr.bp_type;
	lwfp->o_pid = task_tgid_nr(current);
	lwfp->t_pid = task_tgid_nr(event->hw.target);
	lwfp->t_tid = task_pid_nr(event->hw.target);
	lwfp->removed = false;
	refcount_set(&lwfp->refs, 1);

	spin_lock(&target->lwfp_lock);
	list_add_rcu(&lwfp->node, &target->lwfp_list);
	spin_unlock(&target->lwfp_lock);

	return lwfp;

error_copy:
	kfree(lwfp->attr);

error_attr_alloc:
	kfree(lwfp);

	return NULL;
}

static struct lwfp_event *
create_lwfp_event(struct perf_event *event,
		  struct lwfp *lwfp)
{
	struct lwfp_event *new_node;

	new_node = kzalloc(sizeof(*new_node), GFP_KERNEL);
	if (!new_node)
		return NULL;

	new_node->event = event;
	new_node->value = lwfp;
	refcount_set(&new_node->refs, 1);

	return new_node;
}

static struct lwfp_event *
search_for_lwfp(struct perf_event *event)
{
	struct lwfp_event *target_event;

	rcu_read_lock();

	hash_for_each_possible_rcu(events_table,
				   target_event,
				   node,
				   (unsigned long)event) {
		if (target_event->event == event &&
		    refcount_inc_not_zero(&target_event->refs)) {
			rcu_read_unlock();
			return target_event;
		}
	}

	rcu_read_unlock();

	return NULL;
}

static inline int
lwfp_match_extended(struct lwfp *lwfp,
		    struct pt_regs *regs)
{
	return lwfp_match_regs_attr(lwfp ? lwfp->attr : NULL,
				    regs);
}

static inline int
lwfp_match_vm(struct lwfp *lwfp,
	      struct pt_regs *regs)
{
	return lwfp_match_regs_attr(lwfp ? lwfp->attr : NULL,
				    regs);
}

/*
 * SGX matching:
 *   1. regs->bx (host exception context) is the current TCS.
 *   2. Confirm the TCS belongs to this lwfp's enclave.
 *   3. Compute + validate the GPRSGX address (userspace, in-VMA).
 *   4. Read the GPRSGX area once and cache it in sgx_state.
 *   5. Rebuild a local pt_regs from the cached gprs_t.
 *   6. Run the generic attribute matcher against that local
 *      pt_regs; this handles the enclave-internal IP automatically
 *      via sgx_regs.ip.
 *
 * The host regs->ip (interruption IP) is never compared here.
 */
static int
lwfp_match_sgx(struct lwfp *lwfp,
	       struct task_struct *task,
	       struct pt_regs *regs,
	       struct lwfp_sgx_match_state *state)
{
	u64 tcs_addr;
	u64 sgx_ip;
	size_t i;
	int ret;

	if (!lwfp || !lwfp->attr || !lwfp->sgx_attr ||
	    !task || !regs || !state)
		return -EINVAL;

	tcs_addr = regs->bx;
	if (!tcs_addr)
		return 0;

	for (i = 0; i < lwfp->sgx_attr->tcs_count; i++) {
		if (lwfp->sgx_attr->tcs_bases[i] == tcs_addr)
			break;
	}

	if (i == lwfp->sgx_attr->tcs_count)
		return 0;

	if (!state->gprs_valid) {
		void *addr;

		addr = lwfp_sgx_get_gprsgx_addr(
			task,
			lwfp->sgx_attr->enclave_base,
			tcs_addr,
			lwfp->sgx_attr->ssa_framesize);
		if (!addr)
			return -EFAULT;

		state->gprsgx_addr = (u64)(unsigned long)addr;
		/*lets compare the rip first*/
		u64 rip_addr = ((u64)addr) + offset(struct gprs, rip);

		ret = lwfp_sgx_access_enclave(
				task,
				rip_addr,
				&start->gprs.rip,
				sizeof(u64),
				false);
		if (ret)
			return ret;
		if (state->regs.ip != lwfp->attr->context0)
			return 0;
		/*end*/

		ret = lwfp_sgx_access_enclave(
			task,
			(unsigned long)state->gprsgx_addr,
			&state->gprs,
			sizeof(state->gprs),
			false);
		if (ret)
			return ret;

		state->gprs_valid = true;
	} else {//state is valid, check RIP and short cut
		if (state->regs.ip != lwfp->attr->context0)
			return 0;
	}

	memset(&state->regs, 0, sizeof(state->regs));

	state->regs.ax = state->gprs.rax;
	state->regs.bx = state->gprs.rbx;
	state->regs.cx = state->gprs.rcx;
	state->regs.dx = state->gprs.rdx;
	state->regs.si = state->gprs.rsi;
	state->regs.di = state->gprs.rdi;
	state->regs.bp = state->gprs.rbp;
	state->regs.sp = state->gprs.rsp;

	state->regs.r8 = state->gprs.r8;
	state->regs.r9 = state->gprs.r9;
	state->regs.r10 = state->gprs.r10;
	state->regs.r11 = state->gprs.r11;
	state->regs.r12 = state->gprs.r12;
	state->regs.r13 = state->gprs.r13;
	state->regs.r14 = state->gprs.r14;
	state->regs.r15 = state->gprs.r15;

	state->regs.flags = state->gprs.rflags;
	state->regs.ip = state->gprs.rip;

	return lwfp_match_regs_attr(lwfp->attr, &state->regs);
}

#if defined(CONFIG_KVM)

int lwfp_handle_kvm_exception_context(struct kvm_vcpu *vcpu,
				      struct pt_regs *regs,
				      int orig_ret)
{
	struct process_node *proc_item;
	struct thread_node *thread_item;
	struct lwfp *lwfp;
	pid_t pid;
	pid_t tid;
	int found = 0;
	int ret;

	if (orig_ret < 0 || !vcpu || !regs)
		return orig_ret;

	if ((vcpu->guest_debug &
	     (KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP)) !=
	    (KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP))
		return orig_ret;

	if (vcpu->run->exit_reason != KVM_EXIT_DEBUG)
		return orig_ret;

	pid = task_tgid_nr(current);
	tid = task_pid_nr(current);

	proc_item = lwfp_get_process_node(pid);
	if (!proc_item)
		return orig_ret;

	thread_item = lwfp_get_thread_node(proc_item, tid);
	if (!thread_item) {
		process_node_put(proc_item);
		return orig_ret;
	}

	rcu_read_lock();

	list_for_each_entry_rcu(lwfp,
				 &thread_item->lwfp_list,
				 node) {
		if (lwfp->type != LWFP_TYPE_VM)
			continue;

		if (instruction_pointer(regs) != lwfp->config1)
			continue;

		if (!lwfp_match_vm(lwfp, regs))
			continue;

		if (!refcount_inc_not_zero(&lwfp->refs))
			continue;

		found = 1;
		break;
	}

	rcu_read_unlock();

	thread_node_put(thread_item);
	process_node_put(proc_item);

	if (!found)
		return orig_ret;

	perf_bp_event(lwfp->event, regs);
	ret = lwfp_kvm_handle_flags(lwfp, vcpu, regs);

	lwfp_put(lwfp);

	return ret ? ret : 1;
}

#endif /* CONFIG_KVM */

#if defined(CONFIG_X86_64) && defined(CONFIG_KVM)
extern unsigned long kvm_get_rflags(struct kvm_vcpu *vcpu);

static void
lwfp_x86_get_regs_from_vcpu(struct kvm_vcpu *vcpu,
			    struct pt_regs *regs)
{
	struct kvm_segment kvm_cs, kvm_ss;

	if (!vcpu || !regs)
		return;

    regs->ax  = vcpu->arch.regs[VCPU_REGS_RAX];
    regs->bx  = vcpu->arch.regs[VCPU_REGS_RBX];
    regs->cx  = vcpu->arch.regs[VCPU_REGS_RCX];
    regs->dx  = vcpu->arch.regs[VCPU_REGS_RDX];
    regs->si  = vcpu->arch.regs[VCPU_REGS_RSI];
    regs->di  = vcpu->arch.regs[VCPU_REGS_RDI];
    regs->bp  = vcpu->arch.regs[VCPU_REGS_RBP];
    regs->sp  = vcpu->arch.regs[VCPU_REGS_RSP];
    regs->r8  = vcpu->arch.regs[VCPU_REGS_R8];
    regs->r9  = vcpu->arch.regs[VCPU_REGS_R9];
    regs->r10 = vcpu->arch.regs[VCPU_REGS_R10];
    regs->r11 = vcpu->arch.regs[VCPU_REGS_R11];
    regs->r12 = vcpu->arch.regs[VCPU_REGS_R12];
    regs->r13 = vcpu->arch.regs[VCPU_REGS_R13];
    regs->r14 = vcpu->arch.regs[VCPU_REGS_R14];
    regs->r15 = vcpu->arch.regs[VCPU_REGS_R15];
    regs->ip  = vcpu->arch.regs[VCPU_REGS_RIP];
    regs->flags = kvm_get_rflags(vcpu);
    static_call(kvm_x86_get_segment)(vcpu, &kvm_cs, VCPU_SREG_CS);
    static_call(kvm_x86_get_segment)(vcpu, &kvm_ss, VCPU_SREG_SS);
    regs->cs = kvm_cs.selector;
    regs->ss = kvm_ss.selector;
    regs->orig_ax = regs->ax;
}

static int
lwfp_x86_handle_kvm_nmi(struct kvm_vcpu *vcpu)
{
	struct pt_regs regs;
	int orig_ret;

	if (!vcpu)
		return 0;

	orig_ret = ((lwfp_kvm_nmi_handler_t)
		    atomic_long_read(&kvm_handle_exception_nmi))(vcpu);

	lwfp_x86_get_regs_from_vcpu(vcpu, &regs);

	return lwfp_handle_kvm_exception_context(vcpu, &regs, orig_ret);
}

#endif /* CONFIG_X86_64 && CONFIG_KVM */

#if defined(CONFIG_ARM64) && defined(CONFIG_KVM)

static void
lwfp_arm64_get_regs_from_vcpu(struct kvm_vcpu *vcpu,
			      struct pt_regs *regs)
{
	struct kvm_regs *guest_regs;
	unsigned int i;

	guest_regs = vcpu_gp_regs(vcpu);

	for (i = 0; i < ARRAY_SIZE(guest_regs->regs); i++)
		regs->regs[i] = guest_regs->regs[i];

	regs->sp = guest_regs->sp;
	regs->pc = guest_regs->pc;
	regs->pstate = guest_regs->pstate;
}

static int
lwfp_arm64_handle_kvm_nmi(struct kvm_vcpu *vcpu)
{
	struct pt_regs regs;
	int orig_ret;

	if (!vcpu)
		return 0;

	orig_ret = ((lwfp_kvm_nmi_handler_t)
		    atomic_long_read(&kvm_handle_exception_nmi))(vcpu);

	lwfp_arm64_get_regs_from_vcpu(vcpu, &regs);

	return lwfp_handle_kvm_exception_context(vcpu, &regs, orig_ret);
}

#endif /* CONFIG_ARM64 && CONFIG_KVM */

#if defined(CONFIG_KVM)

int lwfp_handle_kvm_exception_nmi(struct kvm_vcpu *vcpu)
{
#if defined(CONFIG_X86_64) && defined(CONFIG_KVM)
	return lwfp_x86_handle_kvm_nmi(vcpu);
#elif defined(CONFIG_ARM64) && defined(CONFIG_KVM)
	return lwfp_arm64_handle_kvm_nmi(vcpu);
#else
	return 1;
#endif
}

#endif /* CONFIG_KVM */

static struct lwfp *
search_for_event(pid_t pid,
		 pid_t tid,
		 struct pt_regs *regs,
		 struct lwfp_sgx_match_state *sgx_state)
{
	struct process_node *proc_item;
	struct thread_node *thread_item;
	struct lwfp *lwfp;
	int found = 0;

	if (!regs || !sgx_state)
		return NULL;

	proc_item = lwfp_get_process_node(pid);
	if (!proc_item)
		return NULL;

	thread_item = lwfp_get_thread_node(proc_item, tid);
	if (!thread_item) {
		process_node_put(proc_item);
		return NULL;
	}

	rcu_read_lock();

	list_for_each_entry_rcu(lwfp,
				&thread_item->lwfp_list,
				node) {
		switch (lwfp->type) {
		case LWFP_TYPE_NORMAL:
			if (instruction_pointer(regs) != lwfp->config1)
				continue;

			found = 1;
			break;

		case LWFP_TYPE_ENCLAVE:
#if defined(__x86_64__)
			if (lwfp->config2 == regs->bx)
				found = 1;
#endif
			break;

		case LWFP_TYPE_EXTENDED:
			if (instruction_pointer(regs) != lwfp->config1)
				continue;

			found = lwfp_match_extended(lwfp, regs);
			break;

		case LWFP_TYPE_SGX:
			found = lwfp_match_sgx(lwfp,
					       current,
					       regs,
					       sgx_state);
			break;

		case LWFP_TYPE_VM:
			pr_err_ratelimited(
				"lwfp: unsupported LWFP_TYPE_VM in "
				"search_for_event(); VM breakpoints must "
				"be handled by the KVM exception/NMI path\n");
			found = -EINVAL;
			break;

		default:
			break;
		}

		if (found)
			break;
	}

	if (found > 0 && !refcount_inc_not_zero(&lwfp->refs))
		found = 0;

	rcu_read_unlock();

	thread_node_put(thread_item);
	process_node_put(proc_item);

	if (found <= 0)
		return NULL;

	return lwfp;
}

static void lwfp_event_destroy(struct perf_event *event)
{
	struct process_node *proc_item = NULL;
	struct thread_node *thread = NULL;
	struct lwfp_event *bp_event;
	struct lwfp *lwfp;
	pid_t pid;
	pid_t tid;

	bp_event = search_for_lwfp(event);
	if (!bp_event)
		return;

	lwfp = bp_event->value;
	if (!lwfp || !refcount_inc_not_zero(&lwfp->refs)) {
		lwfp_event_put(bp_event);
		return;
	}

	pid = lwfp->t_pid;
	tid = lwfp->t_tid;

	spin_lock(&events_lock);

	if (!hlist_unhashed(&bp_event->node))
		hash_del_rcu(&bp_event->node);

	spin_unlock(&events_lock);

	lwfp_put(lwfp);

	proc_item = lwfp_get_process_node(pid);
	if (proc_item) {
		thread = lwfp_get_thread_node(proc_item, tid);

		if (thread) {
			remove_and_free_lwfp(thread, lwfp);

			spin_lock(&thread->lwfp_lock);

			if (list_empty(&thread->lwfp_list))
				remove_thread(proc_item, thread);

			spin_unlock(&thread->lwfp_lock);

			thread_node_put(thread);
		}

		if (unlink_empty_process(proc_item))
			process_node_put(proc_item);

		process_node_put(proc_item);
	}

	lwfp_put(lwfp);

	lwfp_event_put(bp_event);

	return;
}

static int lwfp_event_init(struct perf_event *event)
{
	struct process_node *proc_item = NULL;
	struct thread_node *thread = NULL;
	struct lwfp_event *target_event = NULL;
	struct lwfp_event *existing_event;
	struct lwfp *lwfp = NULL;
	bool process_created = false;
	bool thread_created = false;
	pid_t pid;
	pid_t tid;
	int ret = -ENOMEM;

	if ((event->attr.bp_type == LWFP_TYPE_VM ||
	     event->attr.bp_type == LWFP_TYPE_SGX ||
	     event->attr.bp_type == LWFP_TYPE_EXTENDED) &&
	    event->attr.config2 == 0)
		return -EINVAL;

	pid = task_tgid_nr(current);
	tid = task_pid_nr(event->hw.target);

	spin_lock(&lwfp_module_lock);

	hash_for_each_possible(lwfp_module, proc_item, node, pid) {
		if (proc_item->pid == pid) {
			refcount_inc(&proc_item->refcount);
			break;
		}
	}

	if (!proc_item) {
		proc_item = kzalloc(sizeof(*proc_item), GFP_ATOMIC);
		if (proc_item) {
			proc_item->pid = pid;
			spin_lock_init(&proc_item->thread_lock);
			hash_init(proc_item->thread_hashtable);
			refcount_set(&proc_item->refcount, 2);

			hash_add_rcu(lwfp_module,
				     &proc_item->node,
				     pid);
			process_created = true;
		}
	}

	spin_unlock(&lwfp_module_lock);

	if (!proc_item)
		return -ENOMEM;

	spin_lock(&proc_item->thread_lock);

	hash_for_each_possible(proc_item->thread_hashtable,
			       thread,
			       node,
			       tid) {
		if (thread->tid == tid) {
			refcount_inc(&thread->refcount);
			break;
		}
	}

	if (!thread) {
		thread = kzalloc(sizeof(*thread), GFP_ATOMIC);
		if (thread) {
			thread->tid = tid;
			INIT_LIST_HEAD(&thread->lwfp_list);
			spin_lock_init(&thread->lwfp_lock);
			refcount_set(&thread->refcount, 2);

			hash_add_rcu(proc_item->thread_hashtable,
				     &thread->node,
				     tid);
			thread_created = true;
		}
	}

	spin_unlock(&proc_item->thread_lock);

	if (!thread)
		goto process_cleanup;

	lwfp = add_new_lwfp(event, thread);
	if (!lwfp)
		goto thread_cleanup;

	target_event = create_lwfp_event(event, lwfp);
	if (!target_event)
		goto lwfp_cleanup;

	spin_lock(&events_lock);

	hash_for_each_possible(events_table,
			       existing_event,
			       node,
			       (unsigned long)event) {
		if (existing_event->event == event) {
			spin_unlock(&events_lock);
			ret = -EEXIST;
			goto event_cleanup;
		}
	}

	hash_add_rcu(events_table,
		     &target_event->node,
		     (unsigned long)event);
	refcount_inc(&lwfp->refs);

	spin_unlock(&events_lock);

	thread_node_put(thread);
	process_node_put(proc_item);

	event->destroy = lwfp_event_destroy;

	return 0;

event_cleanup:
	lwfp_event_put(target_event);

lwfp_cleanup:
	remove_and_free_lwfp(thread, lwfp);

thread_cleanup:
	if (thread_created)
		remove_thread(proc_item, thread);

	thread_node_put(thread);

process_cleanup:
	process_node_put(proc_item);

	if (process_created)
		remove_process(pid);

	return ret;
}

static int lwfp_add(struct perf_event *event,
		    int flags)
{
	return 0;
}

static void lwfp_del(struct perf_event *event,
		     int flags)
{
}

static void lwfp_start(struct perf_event *event,
		       int flags)
{
	event->hw.state = 0;
}

static void lwfp_stop(struct perf_event *event,
		      int flags)
{
	event->hw.state = PERF_HES_STOPPED;
}

static void lwfp_pmu_read(struct perf_event *event)
{
}

static struct pmu perf_lwfp = {
	.task_ctx_nr = perf_sw_context,
	.event_init = lwfp_event_init,
	.add = lwfp_add,
	.del = lwfp_del,
	.start = lwfp_start,
	.stop = lwfp_stop,
	.read = lwfp_pmu_read,
};

#if defined(CONFIG_KVM)

static void lwfp_restore_kvm_exception_nmi(void)
{
	void *current_handler;

	current_handler = kvm_switch_handle_exception_nmi(
		kvm_original_handle_exception_nmi);

	WARN_ON_ONCE(current_handler !=
		     (void *)lwfp_handle_kvm_exception_nmi);

	atomic_long_set(&kvm_handle_exception_nmi,
			(long)lwfp_default_kvm_handle_exception_nmi);
}

#endif /* CONFIG_KVM */

int __init init_lwfp(void)
{
	int ret;

#if defined(CONFIG_KVM)
	void *old_handler;
#endif

	hash_init(lwfp_module);
	spin_lock_init(&lwfp_module_lock);

	hash_init(events_table);
	spin_lock_init(&events_lock);

	ret = perf_pmu_register(&perf_lwfp,
				"lwfp_breakpoint",
				PERF_TYPE_LWFP);
	if (ret)
		return ret;

#if defined(CONFIG_KVM)
	old_handler = kvm_switch_handle_exception_nmi(
		(void *)lwfp_handle_kvm_exception_nmi);

	kvm_original_handle_exception_nmi = old_handler;

	if (old_handler)
		atomic_long_set(&kvm_handle_exception_nmi,
				(long)old_handler);
#endif

	ret = register_die_notifier(&lwfp_exceptions_nb);
	if (ret) {
#if defined(CONFIG_KVM)
		lwfp_restore_kvm_exception_nmi();
#endif
		perf_pmu_unregister(&perf_lwfp);
	}

	return ret;
}

void __exit exit_lwfp(void)
{
	unregister_die_notifier(&lwfp_exceptions_nb);

#if defined(CONFIG_KVM)
	lwfp_restore_kvm_exception_nmi();
#endif

	perf_pmu_unregister(&perf_lwfp);
}

void unregister_lwfp(struct perf_event *event)
{
	if (event)
		perf_event_release_kernel(event);
}
EXPORT_SYMBOL_GPL(unregister_lwfp);
