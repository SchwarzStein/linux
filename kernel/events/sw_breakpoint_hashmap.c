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

#include <asm/ptrace.h>
#include <linux/perf_event.h>
#include <linux/kvm_host.h>
#include <uapi/linux/sw_breakpoint.h>

#define EVENT_HTABLE_WIDTH 	16 /*global events here*/
#define LWFP_MODULE_WIDTH 	4 /*process nodes here*/
#define PROC_TABLE_WIDTH 	4 /*threads items here*/


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
	[ARM64_REG_X0]  = offsetof(struct pt_regs, regs[0]),  [ARM64_REG_X1]  = offsetof(struct pt_regs, regs[1]),
	[ARM64_REG_X2]  = offsetof(struct pt_regs, regs[2]),  [ARM64_REG_X3]  = offsetof(struct pt_regs, regs[3]),
	[ARM64_REG_X4]  = offsetof(struct pt_regs, regs[4]),  [ARM64_REG_X5]  = offsetof(struct pt_regs, regs[5]),
	[ARM64_REG_X6]  = offsetof(struct pt_regs, regs[6]),  [ARM64_REG_X7]  = offsetof(struct pt_regs, regs[7]),
	[ARM64_REG_X8]  = offsetof(struct pt_regs, regs[8]),  [ARM64_REG_X9]  = offsetof(struct pt_regs, regs[9]),
	[ARM64_REG_X10] = offsetof(struct pt_regs, regs[10]), [ARM64_REG_X11] = offsetof(struct pt_regs, regs[11]),
	[ARM64_REG_X12] = offsetof(struct pt_regs, regs[12]), [ARM64_REG_X13] = offsetof(struct pt_regs, regs[13]),
	[ARM64_REG_X14] = offsetof(struct pt_regs, regs[14]), [ARM64_REG_X15] = offsetof(struct pt_regs, regs[15]),
	[ARM64_REG_X16] = offsetof(struct pt_regs, regs[16]), [ARM64_REG_X17] = offsetof(struct pt_regs, regs[17]),
	[ARM64_REG_X18] = offsetof(struct pt_regs, regs[18]), [ARM64_REG_X19] = offsetof(struct pt_regs, regs[19]),
	[ARM64_REG_X20] = offsetof(struct pt_regs, regs[20]), [ARM64_REG_X21] = offsetof(struct pt_regs, regs[21]),
	[ARM64_REG_X22] = offsetof(struct pt_regs, regs[22]), [ARM64_REG_X23] = offsetof(struct pt_regs, regs[23]),
	[ARM64_REG_X24] = offsetof(struct pt_regs, regs[24]), [ARM64_REG_X25] = offsetof(struct pt_regs, regs[25]),
	[ARM64_REG_X26] = offsetof(struct pt_regs, regs[26]), [ARM64_REG_X27] = offsetof(struct pt_regs, regs[27]),
	[ARM64_REG_X28] = offsetof(struct pt_regs, regs[28]), [ARM64_REG_X29] = offsetof(struct pt_regs, regs[29]),
	[ARM64_REG_X30] = offsetof(struct pt_regs, regs[30]), [ARM64_REG_SP]  = offsetof(struct pt_regs, sp),
};
#endif

struct lwfp
{
	uint64_t 	base_addr;
	struct 		perf_event *event;
	uint64_t 	config1;
	uint64_t 	config2;
	pid_t 		o_pid;
	pid_t 		t_pid;
	pid_t 		t_tid;
	enum lwfp_type type;
	struct perf_lwfp_attr *attr;
	struct list_head node;
	struct rcu_head rcu;
	bool removed;
	refcount_t refs;
};

struct thread_node
{
	pid_t tid;
	struct list_head lwfp_list; /*all the breakpoints of this thread*/
	struct hlist_node node;/*entry into parent process' hashtable*/
	spinlock_t lwfp_lock;
	struct rcu_head rcu;
	refcount_t refcount;
};

struct process_node
{
	pid_t pid;
	struct hlist_node node; /*entry into global process list*/
	DECLARE_HASHTABLE(thread_hashtable, PROC_TABLE_WIDTH);
	spinlock_t thread_lock;
	struct rcu_head rcu;
	refcount_t refcount;
};

struct lwfp_event
{
	struct perf_event *event; /*key*/
	struct lwfp 	  *value; /*value*/
	struct hlist_node  node;
	struct rcu_head rcu;
	refcount_t refs;
};

struct lwfp_context
{
	struct perf_lwfp_attr *lwfp_attr;
	struct perf_event *event;
	struct pt_regs *regs;
};

DEFINE_HASHTABLE(lwfp_module, LWFP_MODULE_WIDTH); /* declare a 16 bucket hashtable.*/
DEFINE_HASHTABLE(events_table, EVENT_HTABLE_WIDTH); /* allows quick searching of breakpoint. */

static spinlock_t lwfp_module_lock;
static spinlock_t events_lock;

#if defined(CONFIG_X86_64) && defined(CONFIG_KVM)
void *kvm_switch_handle_exception_nmi(void *new);
static int (*kvm_vmx_x86_handle_exception_nmi)(struct kvm_vcpu *vcpu);
#endif

static void lwfp_rcu_free(struct rcu_head *rcu)
{
	struct lwfp *lwfp;

	lwfp = container_of(rcu, struct lwfp, rcu);
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

static inline int lwfp_match_regs_attr(const struct perf_lwfp_attr *attr,
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

	for_each_set_bit(bit_index, &match_bitmap, MAX_REGISTER_MATCH_COUNT) {
#if defined(__x86_64__) || defined(__aarch64__)
		reg_value = regs_get_register((struct pt_regs *)regs, arch_reg_offsets[bit_index]);
#else
		reg_value = 0;
#endif
		if (reg_value != attr->regs[bit_index])
			return 0;
		count++;
	}

	return (count > 0);
}

int lwfp_exceptions_notify(struct notifier_block *unused,
				      unsigned long val, void *data)
{
	struct die_args *args = data;
	struct pt_regs *regs;
	struct lwfp *lwfp;
	int ret;

	if (val != DIE_INT3)
		return NOTIFY_DONE;

	if (!args || !args->regs)
		return NOTIFY_DONE;

	regs = args->regs;

	if (!user_mode(regs))
		return NOTIFY_DONE;

	lwfp = search_for_event(task_tgid_nr(current),
				task_pid_nr(current), regs);
	if (!lwfp)
		return NOTIFY_DONE;

	ret = execute_event(lwfp, regs);
	lwfp_put(lwfp);

	return ret;
}

static
int execute_event(struct lwfp *target, struct pt_regs *regs)
{
	if (!target || !target->event || !regs)
		return NOTIFY_DONE;

	switch (target->type) {
	case LWFP_TYPE_NORMAL:
	case LWFP_TYPE_ENCLAVE:
		return perf_bp_event(target->event, regs);

	case LWFP_TYPE_EXTENDED:
	case LWFP_TYPE_SGX:
	case LWFP_TYPE_VM:
		/* Type-specific post-processing goes here. */
		return NOTIFY_STOP;

	default:
		return NOTIFY_DONE;
	}
}

static struct notifier_block lwfp_exceptions_nb = {
	.notifier_call = lwfp_exceptions_notify,
	/* we need to be notified first */
	.priority = 0x7fffffff
};

static inline void kick_not_current_thread(struct perf_event *event)
{
	pid_t ctid = task_pid_nr(current);
	pid_t ttid = task_pid_nr(event->hw.target);

	if (ctid != ttid) {
		kick_process(event->hw.target);
	}
}

static int
remove_and_free_lwfp(struct thread_node *thread, struct lwfp *bp)
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
get_thread_node(struct process_node *proc, pid_t tid)
{
	struct thread_node *thread;

	if (!proc) return NULL;

	rcu_read_lock();
	hash_for_each_possible_rcu(proc->thread_hashtable, thread, node, tid) {
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
get_process_node(pid_t pid)
{
	struct process_node *proc;

	rcu_read_lock();
	hash_for_each_possible_rcu(lwfp_module, proc, node, pid) {
		if (proc->pid == pid &&
		    refcount_inc_not_zero(&proc->refcount)) {
			rcu_read_unlock();
			return proc;
			break;
		}
	}
	rcu_read_unlock();
	return NULL;
}

static int
remove_process(pid_t pid)
{
	struct process_node *proc;
	bool empty;
	bool removed = false;

	proc = get_process_node(pid);
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

	/* Lookup reference. */
	process_node_put(proc);

	/* Hash-table ownership reference. */
	if (removed)
		process_node_put(proc);

	return removed;
}

static struct thread_node *
add_new_thread(struct process_node *node, pid_t tid)
{
	struct thread_node *new_thread = NULL;

	new_thread = kzalloc(sizeof(struct thread_node), GFP_KERNEL);
	if (!new_thread) return NULL;

	new_thread->tid = tid;
	INIT_LIST_HEAD(&new_thread->lwfp_list);

	spin_lock_init(&new_thread->lwfp_lock);
	refcount_set(&new_thread->refcount, 1);
	spin_lock(&node->thread_lock);

	hash_add_rcu(node->thread_hashtable, &new_thread->node, tid);
	spin_unlock(&node->thread_lock);

	return new_thread;
}

static void *
add_new_lwfp(struct perf_event *event, struct thread_node *target)
{
	struct lwfp *lwfp;
	unsigned long count;
	/*TODO: check if this is in IRQ */

	lwfp = kzalloc(sizeof(struct lwfp), GFP_KERNEL);
	if (lwfp == NULL)
		return NULL;

	lwfp->config1 = event->attr.config1;
	lwfp->config2 = event->attr.config2;
	lwfp->type    = event->attr.bp_type;
	lwfp->o_pid   = task_tgid_nr(current);
	lwfp->t_pid   = task_tgid_nr(event->hw.target);
	lwfp->t_tid   = task_pid_nr(event->hw.target);
	lwfp->removed = false;
	refcount_set(&lwfp->refs, 1);

	if (lwfp->type == LWFP_TYPE_VM || lwfp->type == LWFP_TYPE_SGX ||
			lwfp->type == LWFP_TYPE_EXTENDED) {
		if (lwfp->config2 == 0) goto error_alloc;

		lwfp->attr = kzalloc(sizeof(struct perf_lwfp_attr), GFP_KERNEL);
		if (lwfp->attr == NULL) goto error_alloc;
	}

	if (lwfp->attr) {
		count = copy_from_user(lwfp->attr,
				       u64_to_user_ptr(event->attr.config2),
				       sizeof(struct perf_lwfp_attr));
		if (count != 0) {
			kfree(lwfp->attr);
			lwfp->attr = NULL;
			goto error_alloc;
		}
	}

	spin_lock(&target->lwfp_lock);
	list_add_rcu(&lwfp->node, &target->lwfp_list);
	spin_unlock(&target->lwfp_lock);

	return lwfp;
error_alloc:
		kfree(lwfp);
		return NULL;
}

static struct process_node *
add_new_process(pid_t pid)
{
	struct process_node *new_node;

	new_node = kzalloc(sizeof(struct process_node), GFP_KERNEL);
	if (!new_node) return NULL;

	new_node->pid = pid;

	spin_lock_init(&new_node->thread_lock);
	hash_init(new_node->thread_hashtable);
	refcount_set(&new_node->refcount, 1);
	spin_lock(&lwfp_module_lock);

	hash_add_rcu(lwfp_module, &new_node->node, pid);
	spin_unlock(&lwfp_module_lock);

	return new_node;
}

static struct lwfp_event *
create_lwfp_event(struct perf_event *event, struct lwfp *lwfp)
{
	struct lwfp_event *new_node;

	new_node = kzalloc(sizeof(struct lwfp_event), GFP_KERNEL);
	if (!new_node) return NULL;

	new_node->event = event;
	new_node->value = lwfp;
	refcount_set(&new_node->refs, 1);
	return new_node;
}

static struct lwfp_event *
search_for_lwfp(struct perf_event *event)
{
	struct lwfp_event *target_event = NULL;

	rcu_read_lock();
	hash_for_each_possible_rcu(events_table, target_event, node, (unsigned long)event) {
		if (event == target_event->event &&
		    refcount_inc_not_zero(&target_event->refs)) {
			rcu_read_unlock();
			return target_event;
		}
	}
	rcu_read_unlock();
	return NULL;
}

inline int match_lwfp_extended(struct lwfp *lwfp, struct pt_regs *regs)
{
	return lwfp_match_regs_attr(lwfp ? lwfp->attr : NULL, regs);
}

inline int match_lwfp_vm(struct lwfp *lwfp, struct pt_regs *regs)
{
	return lwfp_match_regs_attr(lwfp ? lwfp->attr : NULL, regs);
}

inline int match_lwfp_sgx(struct lwfp *lwfp, struct pt_regs *regs)
{
	return lwfp_match_regs_attr(lwfp ? lwfp->attr : NULL, regs);
}

#if defined(CONFIG_X86_64) && defined(CONFIG_KVM)

void get_regs_from_vcpu(struct kvm_vcpu *vcpu, struct pt_regs *regs)
{
    regs->ax  = kvm_rax_read(vcpu);
    regs->bx  = kvm_rbx_read(vcpu);
    regs->cx  = kvm_rcx_read(vcpu);
    regs->dx  = kvm_rdx_read(vcpu);
    regs->si  = kvm_rsi_read(vcpu);
    regs->di  = kvm_rdi_read(vcpu);
    regs->bp  = kvm_rbp_read(vcpu);
    regs->sp  = kvm_rsp_read(vcpu);
    regs->ip  = kvm_rip_read(vcpu);

#ifdef CONFIG_X86_64
    regs->r8  = kvm_r8_read(vcpu);
    regs->r9  = kvm_r9_read(vcpu);
    regs->r10 = kvm_r10_read(vcpu);
    regs->r11 = kvm_r11_read(vcpu);
    regs->r12 = kvm_r12_read(vcpu);
    regs->r13 = kvm_r13_read(vcpu);
    regs->r14 = kvm_r14_read(vcpu);
    regs->r15 = kvm_r15_read(vcpu);
#endif

    regs->flags = static_call(kvm_x86_get_rflags)(vcpu);

    regs->cs = static_call(kvm_x86_get_segment)(vcpu, VCPU_SREG_CS).selector;
    regs->ss = static_call(kvm_x86_get_segment)(vcpu, VCPU_SREG_SS).selector;
}

int lwfp_handle_kvm_x86_exception_nmi(struct kvm_vcpu *vcpu)
{
	struct pt_regs regs;

	struct process_node *proc_item;
	struct thread_node *thread_item;
	struct lwfp *lwfp;
	int found = 0;
	int ret;
	pid_t pid;
	pid_t tid;

	if (kvm_vmx_x86_handle_exception_nmi)
		ret = kvm_vmx_x86_handle_exception_nmi(vcpu);
	else
		ret = NOTIFY_DONE;

	/*if the vcpu has no debug enabled, skip*/
	if (!(vcpu->guest_debug & KVM_GUESTDBG_USE_BP))
		return ret;

	if (vcpu->run->exit_reason != KVM_EXIT_DEBUG )
		return ret;

	get_regs_from_vcpu(vcpu, &regs);

	pid = task_tgid_nr(current);
	tid = task_pid_nr(current);

	proc_item = get_process_node(pid);
	if (!proc_item) return ret;

	thread_item = get_thread_node(proc_item, tid);

	if (!thread_item) {
		process_node_put(proc_item);
		return ret;
	}

	rcu_read_lock();
	list_for_each_entry_rcu(lwfp, &thread_item->lwfp_list, node) {
		if (lwfp->type != LWFP_TYPE_VM)
			continue;
		if (instruction_pointer(&regs) != lwfp->config1)
			continue;
		if (match_lwfp_vm(lwfp, &regs) &&
		    refcount_inc_not_zero(&lwfp->refs)) {
			found = 1;
			break;
		}
	}
	rcu_read_unlock();

	thread_node_put(thread_item);
	process_node_put(proc_item);

	if (!found)
		return ret;
	/*ensure uniqueness during setup*/
	ret = perf_bp_event(lwfp->event, &regs);
	lwfp_put(lwfp);
	return ret;
}

#endif

inline struct lwfp *
search_for_event(pid_t pid, pid_t tid, struct pt_regs *regs)
{
	struct process_node *proc_item;
	struct thread_node *thread_item;
	struct lwfp *lwfp;
	int found = 0;

	proc_item = get_process_node(pid);
	if (!proc_item)
		return NULL;

	thread_item = get_thread_node(proc_item, tid);
	if (!thread_item) {
		process_node_put(proc_item);
		return NULL;
	}

	rcu_read_lock();
	list_for_each_entry_rcu(lwfp, &thread_item->lwfp_list, node) {
		if (instruction_pointer(regs) != lwfp->config1)
			continue;

		switch(lwfp->type) {
		case LWFP_TYPE_NORMAL:
			found = 1;
			break;
		case LWFP_TYPE_ENCLAVE:
#if defined(__x86_64__)
			if (lwfp->config2 == regs->bx)
				found = 1;
#endif
			break;
		case LWFP_TYPE_EXTENDED:
			found = match_lwfp_extended(lwfp, regs);
			break;
		case LWFP_TYPE_SGX:
			found = match_lwfp_sgx(lwfp, regs);
			break;
		case LWFP_TYPE_VM:
			found = match_lwfp_vm(lwfp, regs);
			break;
		default:
			break;
		}
		if (found) break;
	}

	if (found && !refcount_inc_not_zero(&lwfp->refs))
		found = 0;

	rcu_read_unlock();
	thread_node_put(thread_item);
	process_node_put(proc_item);

	if (!found)
		return NULL;
	return lwfp;
}

inline struct perf_event *
event_from_context(struct pt_regs *regs)
{
 	struct lwfp *lwfp = NULL;
	struct lwfp_event *target_event;

 	pid_t pid;
	pid_t tid;

	pid = task_tgid_nr(current);
	tid = task_pid_nr(current);

	lwfp = search_for_event(pid, tid, regs);
	if (!lwfp)
		return NULL;

	target_event = search_for_lwfp(lwfp->event);
	lwfp_put(lwfp);
	if (!target_event)
		return NULL;

	{
		struct perf_event *event = target_event->event;
		lwfp_event_put(target_event);
		return event;
	}
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

	/*
	 * Find or create the process atomically.
	 *
	 * One reference belongs to lwfp_module. A second reference belongs
	 * to this event-init operation.
	 */
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

			hash_add_rcu(lwfp_module, &proc_item->node, pid);
			process_created = true;
		}
	}

	spin_unlock(&lwfp_module_lock);

	if (!proc_item)
		return -ENOMEM;

	/*
	 * Find or create the thread atomically.
	 *
	 * One reference belongs to proc_item->thread_hashtable. A second
	 * reference belongs to this event-init operation.
	 */
	spin_lock(&proc_item->thread_lock);

	hash_for_each_possible(proc_item->thread_hashtable, thread, node, tid) {
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
				     &thread->node, tid);
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

	/*
	 * Duplicate checking and insertion must be performed under the
	 * same lock.
	 */
	spin_lock(&events_lock);

	hash_for_each_possible(events_table, existing_event, node,
			       (unsigned long)event) {
		if (existing_event->event == event) {
			spin_unlock(&events_lock);
			ret = -EEXIST;
			goto event_cleanup;
		}
	}

	/*
	 * target_event->refs == 1 is the events_table ownership.
	 *
	 * lwfp->refs == 1 is the thread list ownership. The event table
	 * takes an additional LWFP reference.
	 */
	hash_add_rcu(events_table, &target_event->node,
		     (unsigned long)event);
	refcount_inc(&lwfp->refs);

	spin_unlock(&events_lock);

	/* Release the local operation references. */
	thread_node_put(thread);
	process_node_put(proc_item);

	return 0;

event_cleanup:
	lwfp_event_put(target_event);

lwfp_cleanup:
	remove_and_free_lwfp(thread, lwfp);

thread_cleanup:
	if (thread_created)
		remove_thread(proc_item, thread);

	/* Release the local thread reference. */
	thread_node_put(thread);

process_cleanup:
	/* Release the local process reference. */
	process_node_put(proc_item);

	/*
	 * If this function created the process, no other thread can own it
	 * after the thread cleanup above, so remove its hash-table entry.
	 */
	if (process_created)
		remove_process(pid);

	return ret;
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

static int lwfp_event_destroy(struct perf_event *event)
{
	struct process_node *proc_item = NULL;
	struct thread_node *thread = NULL;
	struct lwfp_event *bp_event;
	struct lwfp *lwfp;
	pid_t pid;
	pid_t tid;

	bp_event = search_for_lwfp(event);
	if (!bp_event)
		return 0;

	lwfp = bp_event->value;
	if (!lwfp || !refcount_inc_not_zero(&lwfp->refs)) {
		/*
		 * Drop the lookup reference acquired by
		 * search_for_lwfp().
		 */
		lwfp_event_put(bp_event);
		return 0;
	}

	pid = lwfp->t_pid;
	tid = lwfp->t_tid;

	/*
	 * Remove the event-table entry. The initial bp_event reference
	 * belongs to the event table; the lookup reference remains held
	 * until the end of this function.
	 */
	spin_lock(&events_lock);
	if (!hlist_unhashed(&bp_event->node))
		hash_del_rcu(&bp_event->node);
	spin_unlock(&events_lock);

	/* Drop the event-table reference to lwfp. */
	lwfp_put(lwfp);

	proc_item = get_process_node(pid);
	if (proc_item) {
		thread = get_thread_node(proc_item, tid);
		if (thread) {
			/* Drops the list-owned LWFP reference. */
			remove_and_free_lwfp(thread, lwfp);

			/* Remove an empty thread from the process table. */
			spin_lock(&thread->lwfp_lock);
			if (list_empty(&thread->lwfp_list))
				remove_thread(proc_item, thread);
			spin_unlock(&thread->lwfp_lock);

			/* Drop the lookup reference from get_thread_node(). */
			thread_node_put(thread);
		}

		/*
		 * Remove and RCU-free an empty process. Do not inspect
		 * refcount_t directly and do not call kfree() here.
		 */
		if (unlink_empty_process(proc_item))
			/* Drop the process-table reference. */
			process_node_put(proc_item);

		/* Drop the lookup reference from get_process_node(). */
		process_node_put(proc_item);
	}

	/* Drop the local LWFP reference acquired above. */
	lwfp_put(lwfp);

	/*
	 * Drop the lookup reference acquired by search_for_lwfp().
	 * The event-table reference was removed above.
	 */
	lwfp_event_put(bp_event);

	return 0;
}

static int lwfp_add(struct perf_event *event, int flags)
{
	/*HB API requires hardware programming in this step*/
	return 0;
}

static void lwfp_del(struct perf_event *event, int flags)
{
	/*HB API requires hardware clearing in this step*/
	return 0;
}

static void lwfp_start(struct perf_event *event, int flags)
{
	/*HB API requires enabling hardware in this step*/
	event->hw.state = 0;
}

static void lwfp_stop(struct perf_event *event, int flags)
{
	/*HB API requires disabling hardware in this step*/
	event->hw.state = PERF_HES_STOPPED;
}

void lwfp_pmu_read(struct perf_event *event)
{
	//read the given pmu into the event
}

static struct pmu perf_lwfp = {
	.task_ctx_nr	= perf_sw_context,
	.event_init	    = lwfp_event_init,
	.add		    = lwfp_add,
	.del		    = lwfp_del,
	.start		    = lwfp_start,
	.stop		    = lwfp_stop,
	.read		    = lwfp_pmu_read,
	.event_destroy  = lwfp_event_destroy,
};

int __init init_lwfp(void)
{
	int ret;
	hash_init(lwfp_module);
	spin_lock_init(&lwfp_module_lock);
	hash_init(events_table);
	spin_lock_init(&events_lock);

	ret = perf_pmu_register(&perf_lwfp,
				"lwfp_breakpoint",
				PERF_TYPE_LWFP_BREAKPOINT);
	if (ret)
		return ret;
	return register_die_notifier(&lwfp_exceptions_nb);
}

void unregister_lwfp(struct perf_event *event)
{
	if (!event) return;
	perf_event_release_kernel(event);
}
EXPORT_SYMBOL_GPL(unregister_lwfp);

