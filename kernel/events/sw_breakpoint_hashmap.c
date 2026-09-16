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
	enum lwfp_type type;
	struct perf_lwfp_attr *attr;
	struct list_head node;
};

struct thread_node
{
	pid_t tid;
	struct list_head lwfp_list; /*all the breakpoints of this thread*/
	struct hlist_node node;/*entry into parent process' hashtable*/
	spinlock_t lwfp_lock;
	int refcount;
};

struct process_node
{
	pid_t pid;
	struct hlist_node node; /*entry into global process list*/
	DECLARE_HASHTABLE(thread_hashtable); /* 16 bucket hashtable for threads.*/
	spinlock_t thread_lock;
	int refcount;
};

struct lwfp_event
{
	struct perf_event *event; /*key*/
	struct lwfp 	  *value; /*value*/
	struct hlist_node  node;
};

struct lwfp_context
{
	struct lwfp_attr *lwfp_attr;
	struct perf_event *event;
	struct pt_regs *regs;
};

DEFINE_HASHTABLE(lwfp_module, LWFP_MODULE_WIDTH); /* declare a 16 bucket hashtable.*/
DEFINE_HASHTABLE(events_table, EVENT_HTABLE_WIDTH); /* allows quick searching of breakpoint. */

static spinlock_t lwfp_module_lock;
static spinlock_t events_lock;

void *kvm_switch_handle_notify(void *new);
static int (*kvm_vmx_x86_exception_nmi)(struct kvm_vcpu *vcpu) = NULL;

int sw_breakpoint_exceptions_notify(struct notifier_block *unused,
					unsigned long val, void *data)
{
	struct die_args *args = data;
	struct pt_regs *regs = args->regs;
	struct perf_event *event = NULL;
	int ret = NOTIFY_DONE;
	long ip = 0;
	pid_t pid = task_tgid_nr(current);
	pid_t tid = task_pid_nr(current);
	pid_t tpid;
	pid_t ttid;

	if (val != DIE_INT3 ) return NOTIFY_DONE;

	if (regs) ip = regs->ip;

	/* only userspace traps */
	if (regs && !user_mode(regs))
		return NOTIFY_DONE;

	event = search_event_by_current(regs);

	if (!event) {
		return ret;
	}

	tpid = task_tgid_nr(event->hw.target);
	ttid = task_pid_nr(event->hw.target);
	ret = execute_event(event, regs);
}

int execute_event(struct perf_event *event, struct pt_regs *regs)
{
	int val;
	switch(target->btype) {
	case LWFP_TYPE_NORMAL:
	case LWFP_TYPE_ENCLAVE:
		val = perf_bp_event(event, regs);
		return val;
		break;
	case LWFP_TYPE_EXTENDED:
	case LWFP_TYPE_SGX:
	case LWFP_TYPE_VM:
		break;
	default:
		break;
	}

	ret = NOTIFY_STOP;
	return ret;
}

static struct notifier_block sw_breakpoint_exceptions_nb = {
	.notifier_call = sw_breakpoint_exceptions_notify,
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
	if (!bp || !thread) return 0;

	spin_lock(&thread->lwfp_lock);
	list_del(&bp->node);
	spin_unlock(&thread->lwfp_lock);

	if (bp->btype == LWFP_TYPE_EXTENDED || bp->type == LWFP_TYPE_VM
			|| bp->type == LWFP_TYPE_SGX) {
		if (bp->attr) kfree(bp->attr);
	}

	kfree(bp);
	return 1;
}

static int
remove_and_free_thread(struct process_node *proc, struct thread_node *tnode)
{
	if (!proc || !tnode) return 0;

	spin_lock(&proc->thread_lock);
	list_del(&tnode->node);
	spin_unlock(&proc->thread_lock);
	kfree(tnode);
	return 1;
}

static int
remove_thread(struct process_node *proc, struct thread_node *thread)
{
	struct thread_node *tnode;

	if (!proc || !tnode) return 0;

	spin_lock(&proc->thread_lock);
	hash_del(proc->thread_hashtable, thread->tid);
	spin_unlock(&proc->thread_lock);

}

static struct thread_node *
get_thread_node(struct process_node *proc, pid_t tid)
{
	struct thread_node *thread;
	struct thread_node *tmp;

	if (!proc) return NULL;

	rcu_read_lock();
	hash_for_each_possible(proc->thread_hashtable, tmp, thread, tid) {
		if (thread->tid == tid) {
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
	struct process_node *temp;

	rcu_read_lock();
	hash_for_each_possible(lwfp_module, temp, proc, node) {
		if (proc->pid == pid) {
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
	int bucket;

	rcu_read_lock();
	hash_for_each_possible(lwfp_module, bucket, proc, node) {
		if (proc->pid == pid)
			break;
	}
	rcu_read_unlock();
	if (proc && proc->pid != pid) return 0;

	struct thread_node *thread;
}

static struct thread_node *
add_new_thread(struct process_node *node, pid_t tid)
{
	struct thread_node *new_thread = NULL;

	new_thread = kzalloc(sizeof(struct thread_node), GPF_KERNEL);
	if (!new_thread) return NULL;
	new_thread->tid = tid;
	INIT_LIST_HEAD(&new_thread->lwfp_list);
	spin_lock(node->thread_lock);
	hash_add_rcu(node->thread_hashtable, new_thread, tid);
	spin_unlock(node->thread_lock);

	return new_thread;
}

static void *
add_new_lwfp(struct perf_event *event, struct thread_node *target)
{
	struct lwfp *lwfp;
	unsigned long count;
	/*TODO: check if this is in IRQ */

	lwfp = kzalloc(sizeof(struct lwfp), GFP_KERNEL);
	if (lwfp == NULL) goto NULL;

	lwfp->config1 = event->attr.config1;
	lwfp->config2 = event->attr.config2;
	lwfp->btype   = event->attr.bp_type;
	lwfp->o_pid   = task_tgid_nr(current);
	lwfp->t_pid   = task_tgid_nr(event->hw.target);
	lwfp->enabled = 0;

	if (lwfp->btype == LWFP_TYPE_VM || lwfp->bytpe == LWFP_TYPE_SGX ||
			lwfp->bytpe == LWFP_TYPE_EXTENDED) {
		if (lwfp->config2 == NULL) goto error_alloc;

		lwfp->attr = kzalloc(sizeof(struct perf_lwfp_attr), GFP_KERNEL);
		if (lwpf->attr == NULL) goto error_alloc;
	}

	count = copy_from_user(lwfp->attr, (void*) event->attr.config2,
			sizeof(struct perf_lwfp_attr));

	if (count != 0) {
		kfree(lwfp->attr);
		goto error_alloc;
	}

	spin_lock(&thread->lock);
	list_add_rcu(&target->lwfp_list, &lwfp->bp_node);
	spin_unlock(&thread->lock);

	return lwfp;
error_alloc:
		kfree(lwfp);
		return NULL;
}

static process_node *
add_new_process(pid_t pid)
{
	struct process_node *new_node;

	new_node = kzalloc(sizeof(struct process_node), GFP_KERNEL);
	if (!new_node) return NULL;

	node->pid = pid;
	spin_lock_init(&node->thread_lock);
	hash_init(node->events_table);
	spin_lock(&lwfp_module_lock);
	hash_add_rcu(lwfp_module, new_node, pid);
	spin_unlock(&lwfp_module_lock);

	return new_node;
}

static struct lwfp_event *
create_lwfp_event(struct perf_event *event, struct lwfp *lwfp)
{
	struct swb_event *new_node;

	new_node = kzalloc(sizeof(struct lwfp_event), GFP_KERNEL);
	if (!new_node) return NULL;

	new_node->event = event;
	new_node->value = lwfp;
	return new_node;
}

static struct lwfp_event *
search_for_lwfp(struct perf_event *event)
{
	struct swpb_event *target_event = NULL;
	struct lwfp_event *cursor = NULL;

	rcu_read_lock();
	hash_for_each_possible_rcu(events_table, target_event, node, event) {
		if (event == target_event->event) {
			rcu_read_unlock();
			return target_event;
		}
	}
	rcu_read_unlock();

	return NULL;
}

inline int match_lwfp_extended(struct lwfp *lwfp, struct pt_regs *regs)
{
	unsigned long match_bitmap;
	unsigned int bit_index;
	uint64_t reg_value;
	int count = 0;

	if (!lwfp) return 0;
	if (!lwfp->attr) return 0;

	match_bitmap = (unsigned long)lwfp->attr->match;

	for_each_set_bit(bit_index, &match_bitmap, MAX_REGISTER_MATCH_COUNT) {
#if defined (__x86_64__)
		reg_value = regs_get_register(regs, arch_reg_offsets[bit_index]);
#elif defined(__aarch64__)
		reg_value = attr->regs[bit_index];
#endif
		if (reg_value != lwfp->attr->regs[bit_index])
			return 0;
		count++;
	}
	return (count > 0);
}


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

	ret =  kvm_vmx_x86_handle_exception_nmi(vcpu);

	/*if the vcpu has no debug enabled, skip*/
	if (!(vcpu->guest_debug & KVM_GUESTDBG_USE_BP))
		return ret;

	if (!(vcpu->run->exit_reason == KVM_EXIT_DEBUG &&
		return ret;
	}

	get_regs_from_vcpu(vcpu, &regs);

	proc_item = get_process_node(pid);
	if (!proc_item) return ret;
	thread_item = get_thread_node(proc_item, tid);
	if (!thread_item) return ret;

	/**/
	list_for_each_entry(lwfp, thread_item, lwfp_list) {
		if (lwfp->type != LWFP_TYPE_VM) continue;
		if (match_lwfp_vm(lwfp, regs)){
			found = 1;
			break;
		}
	}

	if (!found) ;//call other handlers

	found = perf_bp_event(event, regs);

	if (found == 0) {
		if (lwfp->flags & LWFP_RIP_INC) {
			kvm_rip_write(vcpu, regs->ip + 1);
		}
	}
	return 0;
}

inline int match_lwfp_vm(struct lwfp *lwfp, struct pt_regs *regs)
{
	unsigned long match_bitmap;
	unsigned int bit_index;
	uint64_t reg_value;
	int count = 0;

	if (!lwfp) return 0;
	if (!lwfp->attr) return 0;

	match_bitmap = (unsigned long)lwfp->attr->match;

	for_each_set_bit(bit_index, &match_bitmap, MAX_REGISTER_MATCH_COUNT) {
#if defined (__x86_64__)
		reg_value = regs_get_register(regs, arch_reg_offsets[bit_index]);
#elif defined(__aarch64__)
		reg_value = attr->regs[bit_index];
#endif
		if (reg_value != lwfp->attr->regs[bit_index])
			return 0;
		count++;
	}
	return (count > 0);
}

inline int match_lwfp_sgx(struct lwfp *lwfp, struct pt_regs *regs)
{
	int ret_val;
	struct lwfp_context ctx = {
		.lwfp_attr = lwfp->attr,
		.event = lwfp->event,
		.regs = regs,
	};
	ret_val = blocking_notifier_call_chain(&lwfp_sgx_notifier_list, lwfp->type, regs);
	if (ret_val == NOTIFY_DONE)
		return 1;
	return 0;
}

inline struct lwfp *
search_for_event(pid_t pid, pid_t tid, struct pt_regs *regs)
{
	struct process_node *proc_item;
	struct thread_node *thread_item;
	struct lwfp *lwfp;
	int found = 0;

	proc_item = get_process_node(pid);
	if (!proc_item) return NULL;
	thread_item = get_thread_node(proc_item, tid);
	if (!thread_item) return NULL;

	spin_lock(&thread_item->lwfp_lock);
	list_for_each_entry(lwfp, thread_item, lwfp_list) {
		if (instruction_pointer(regs) != lwfp->config1)
			continue;

		switch(lwfp->type) {
		case LWFP_TYPE_NORMAL:
			found = 1;
			break;
		case LWFP_TYPE_ENCLAVE:
		#if defined(__x86_64_)
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
	spin_unlock(&thread_item->lwfp_lock);
	if (!found) lwfp = NULL;

	return lwfp;
}

inline struct perf_event *
event_from_context(struct pt_regs *regs)
{
	struct lwfp_event *target_event = NULL;
	struct lwfp_event *temp_event = NULL;
	struct lwfp *lwfp = NULL;
	struct thread_node *target_thread = NULL;

	pid_t pid;
	pid_t tid;

	pid = task_tgid_nr(current);
	tid = task_pid_nr(current);


	target_event = search_for_lwfp(regs);
	if (target_event == 0) return 0;





}

/* allocate resources for this sw bp. Add it to the list*/
static int sw_breakpoint_event_init(struct perf_event *event)
{
	/* get current pid
	 * get target pid/tid
	 * check if target is in table
	 * allocate if missing or
	 * (a) append if missing or append to bp_list for tid
	 * put to a global hashtable of events
	 * return success
	*/

	struct process_node *proc_item = NULL;
	struct lwfp_event *target_event = NULL;
	struct lwfp *lwfp = NULL;
	struct thread_node *target_thread = NULL;

	int thread_created = 0;
	pid_t pid;
	pid_t tid;

	//check if valid event
	if ( (event->attr.btype == LWFP_TYPE_VM ||
			event->attr.btype == LWFP_TYPE_SGX ||
			event->attr.btype == LWFP_TYPE_EXTENDED) &&
			event->atttr.config2 == 0)
				return -EINVAL;

	pid = task_tgid_nr(current);
	tid = task_pid_nr(current);

	rcu_read_lock();
	hash_for_each_possible_rcu(events_table, target_event, node, event) {
		if (event == target_event->event) {
			rcu_read_unlock();
			return -EEXIST;
		}
	}
	rcu_read_unlock();

	/*it does not exist*/
	/*check if process does not exist*/

	rcu_read_lock();
	hash_for_each_possible_rcu(lwfp_module, proc_item, node, pid) {
		if (proc_item->pid == pid) {
			break;
		}
	}
	rcu_read_unlock();

	if (proc_item == NULL || proc_item->pid != pid) {
		//add a new process node
		proc_item = add_new_process(pid);
		if (proc_item == NULL) return -ENOMEM;//TODO goto
		new_thread = NULL;
	} else {
		//search for thread
		rcu_read_lock();
		hash_for_each_possible_rcu(proc_item->thread_hashtable, target_thread, node, tid) {
			if (new_thread->tid == tid) {
				break;
			}
		}
		rcu_read_unlock();
	}

	if (new_thread == NULL || thread->tid != tid) {
		new_thread = add_new_thread(process_item, tid);
		if (new_thread == NULL) goto thread_fail;
		thread_created = 1;
	}

	//create a new lwfp_node and append to new_thread
	lwfp = add_new_lwfp(event, new_thread);
	if (!lwfp) goto error_lwfp; /*if new proc and new_thread, delete them*/

	target_event = create_lwfp_event(event, lwfp);
	if (!target_event) goto error_lwfp;

	//add item to events hash
	spin_lock(&events_lock);
	hash_add_rcu(&events_table, &lwfp_event->node, event);
	spin_unlock(&events_lock);


	/*register kvm handler*/
	kvm_vmx_x86_handle_exception_nmi = kvm_switch_handle_exception_nmi(lwfp-handle_kvm_notify);

	return 0;

thread_fail:
	return -ENOMEM;

error_lwfp:
	if (thread_created) remove_and_free_thread(proc_item, new_thread);
	if (lwfp) kfree(lwfp);
	return -ENOMEM;
}

static int sw_breakpoint_event_destroy(struct perf_event *event)
{
	struct process_node *proc_item;
	struct thread_node  *thread;
	struct lwfp_event   *bp_event;
	struct lwfp         *lwfp;
	pid_t pid,tid;

	bp_event = search_for_lwfp(event);
	if (!bp_event) return 0;

	lwfp = bp_event->value;
	spin_lock(&events_lock);//TODO reference count
	hash_del_rcu(&bp_event->node);
	spin_unlock(&events_lock);

	proc_item = get_process_node(pid); //TODO: check proc_item

	if (!proc_item) return 0;//TODO: warning

	thread  = get_thread_node(proc_item, tid);
	if (!thread) return 0;

	remove_and_free_lwfp(thread, lwfp);
	kfree(bp_event);

	if (thread->refcount != 0) return 0;

	remove_and_free_thread(proc_item, thread);

	spin_lock(&lwfp_module_lock);
	if (proc_item->refcount == 0) {
		hash_del(lwfp_module, pid);
		kfree(proc_item);
	}
	spin_unlock(&lwfp_module_lock);

	return 0;
}

static int sw_breakpoint_add(struct perf_event *event, int flags)
{
	/*HB API requires hardware programming in this step*/
}

static void sw_breakpoint_del(struct perf_event *event, int flags)
{
	/*HB API requires hardware clearing in this step*/
}

static void sw_breakpoint_start(struct perf_event *event, int flags)
{
	/*HB API requires enabling hardware in this step*/
}

static void sw_breakpoint_stop(struct perf_event *event, int flags)
{
	/*HB API requires disabling hardware in this step*/
	event->hw.state = PERF_HES_STOPPED;
}

void sw_breakpoint_pmu_read(struct perf_event *event)
{
	//read the given pmu into the event
}

static struct pmu perf_sw_breakpoint = {
	.task_ctx_nr	= perf_sw_context,
	.event_init	= sw_breakpoint_event_init,
	.add		= sw_breakpoint_add,
	.del		= sw_breakpoint_del,
	.start		= sw_breakpoint_start,
	.stop		= sw_breakpoint_stop,
	.read		= sw_breakpoint_pmu_read,
};

int __init init_sw_breakpoint(void)
{
	hash_init(lwfp_module);
	spin_lock_init(&lwfp_module_lock);
	hash_init(events_table);
	spin_lock_init(&events_lock);

	perf_pmu_register(&perf_sw_breakpoint, "sw_breakpoint", PERF_TYPE_SW_BREAKPOINT);
	return register_die_notifier(&sw_breakpoint_exceptions_nb);
}

EXPORT_SYMBOL_GPL(unregister_sw_breakpoint);
