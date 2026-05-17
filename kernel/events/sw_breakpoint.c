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
#include <linux/cpu.h>
#include <linux/smp.h>
#include <linux/bug.h>

#include <linux/perf_event.h>
#include <uapi/linux/sw_breakpoint.h>

struct sw_bp_info {
	struct list_head list;
	struct list_head event_list;
	struct thread_node *parent_thread;
	long unsigned int base_addr;
	long unsigned int enc_addr;
	unsigned int enabled;
	unsigned int rid; /*owner of this event*/
	unsigned int tid; /*target of this event*/
	unsigned int pid; /*target of this event*/
	enum swbp_type type;
	struct perf_event *event;
};

struct thread_node {
	struct list_head thread_list;
	struct list_head bp_list;
	struct process_list *parent_proc;
	unsigned int tid;
	spinlock_t lock;
};

struct process_list {
	struct list_head process_list;
	struct list_head thread_list;
	spinlock_t lock;
	atomic_t count;
	int pid;
};

static LIST_HEAD(per_process_list);
/*protect addition and removal from list*/
static DEFINE_SPINLOCK(process_lock);
/*hold mutex before locking this item*/

static inline struct process_list * get_process_list_pid(pid_t pid)
{
	struct list_head *position = NULL;
	struct list_head *n = NULL;
	struct process_list *item = NULL;

	list_for_each_safe(position, n, &per_process_list) {
		item = list_entry(position, struct process_list, process_list);
		if (item) {
			if (item->pid == pid) return item;
		}
	}
	return NULL;
}

static inline struct thread_node * _get_thread_list(struct process_list *list, pid_t tid)
{
	struct list_head *position = NULL;
	struct list_head *n = NULL;
	struct thread_node *item = NULL;

	list_for_each_safe(position, n, &list->thread_list) {
		item = list_entry(position, struct thread_node, thread_list);
		if (item && item->tid == tid) return item;
	}
	return NULL;
}

static inline struct thread_node *get_bp_list(pid_t pid, pid_t tid, struct process_list **list)
{
	struct process_list *pl;
	struct thread_node *tn;
	pl = get_process_list_pid(pid);
	if (!pl) return NULL;

	tn = _get_thread_list(pl, tid);
	if (list) *list = pl;
	return tn;
}

static struct perf_event *search_event_by_current(struct pt_regs *regs)
{
	struct thread_node *thread = NULL;
	struct list_head *position = NULL;
	struct sw_bp_info *sw_item = NULL;
	struct perf_event *event = NULL;
	unsigned long flags;

	pid_t pid = task_tgid_nr(current);
	pid_t tid = task_pid_nr(current);

	spin_lock_irqsave(&process_lock, flags);
	thread = get_bp_list(pid, tid, NULL);
	spin_unlock_irqrestore(&process_lock, flags);

	if (!thread) return NULL;

	spin_lock_irqsave(&thread->lock, flags);
	list_for_each(position, &thread->bp_list) {
		sw_item = list_entry(position, struct sw_bp_info, list);

		if (!sw_item)
			continue;

		if (sw_item->type == SW_BREAKPOINT_ENCLAVE && sw_item->enc_addr != regs->bx) {
			continue;
		}

		if (sw_item->base_addr == regs->ip) {
			event = sw_item->event;
			break;
		}
	}
	spin_unlock_irqrestore(&thread->lock, flags);
	return event;
}

//static struct sw_bp_info * has_event(struct thread_node *tnode, struct perf_event *event)
//{
//	struct list_head *position = NULL;
//	struct sw_bp_info *sw_item  = NULL;
//	unsigned long flags;
//	bool irq = irqs_disabled();
//
//	if (!tnode) return NULL;
//
//	if (irq) spin_lock(&tnode->lock);
//	else spin_lock_irqsave(&tnode->lock, flags);
//
//	list_for_each(position, &tnode->bp_list) {
//		sw_item = list_entry(position, struct sw_bp_info, list);
//		if (sw_item && sw_item->event == event) {
//			if (irq) spin_unlock(&tnode->lock);
//			else spin_unlock_irqrestore(&tnode->lock, flags);
//			return sw_item;
//		}
//	}
//	if (irq) spin_unlock(&tnode->lock);
//	else spin_unlock_irqrestore(&tnode->lock, flags);
//	return NULL;
//}

static struct sw_bp_info * search_by_event_destroy(struct perf_event *event,
			 struct thread_node **rnode, struct process_list **rplist)
{
	struct thread_node *tnode = NULL;
	struct process_list *plist = NULL;
	struct sw_bp_info *info   = NULL;
	//unsigned long flags = 0;
	struct list_head *position;

	if (event->hw.bp_list.next == 0) return NULL;

	list_for_each(position, &event->hw.bp_list) {
		info = list_entry(position, struct sw_bp_info, event_list);
		if (info) break;
	}

	if (info) tnode = info->parent_thread;
	if (tnode) plist = tnode->parent_proc;

	if (tnode && rnode) *rnode = tnode;
	if (plist && rplist) *rplist = plist;

	return info;
}

//static struct sw_bp_info * search_by_event(struct perf_event *event, struct thread_node **rnode, struct process_list **rplist)
//{
//	struct thread_node *tnode = NULL;
//	struct process_list *plist = NULL;
//	struct sw_bp_info *info   = NULL;
//	unsigned long flags = 0;
//	bool irq = irqs_disabled();
//
//	pid_t t_pid;
//	pid_t t_tid;
//	pid_t c_pid = task_tgid_nr(current);
//
//	t_pid = task_tgid_nr(event->hw.target);
//	t_tid = task_pid_nr(event->hw.target);
//
//	if (irq) spin_lock(&process_lock);
//	else spin_lock_irqsave(&process_lock, flags);
//
//	tnode = get_bp_list(t_pid, t_tid, &plist);
//
//	if (!tnode && c_pid != t_pid)
//		tnode = get_bp_list(c_pid, c_pid, &plist);
//
//	if (irq) spin_unlock(&process_lock);
//	else spin_unlock_irqrestore(&process_lock, flags);
//
//	if (!tnode) return NULL;
//
//	info = has_event(tnode, event);
//
//	if (info && rnode)
//		*rnode= tnode;
//
//	if (info && rplist)
//		*rplist = plist;
//
//	return info;
//}

static void swbp_perf_event_destroy(struct perf_event *event)
{
	struct process_list *proc_list = NULL;
	struct thread_node *tnode = NULL;
	struct sw_bp_info *sw_item = NULL;
	unsigned long flags;

	sw_item = search_by_event_destroy(event, &tnode, &proc_list);
	if (!sw_item) {
		//int target = task_tgid_nr(event->hw.target);
		//int pid = task_tgid_nr(current);
		return;
	}

	spin_lock_irqsave(&tnode->lock, flags);
	list_del(&sw_item->list);
	list_del(&event->hw.bp_list);
	atomic_dec(&proc_list->count);
	spin_unlock_irqrestore(&tnode->lock, flags);
	kfree(sw_item);

	if (list_empty(&tnode->bp_list)) {
		spin_lock_irqsave(&proc_list->lock, flags);
		if (list_empty(&tnode->bp_list)) {
			list_del(&tnode->thread_list);
			kfree(tnode);
		}
		spin_unlock_irqrestore(&proc_list->lock, flags);
	}

	if (list_empty(&proc_list->thread_list)) {
		spin_lock_irqsave(&process_lock, flags);
		if (list_empty(&proc_list->thread_list)) {
			list_del(&proc_list->process_list);
			kfree(proc_list);
		}
		spin_unlock_irqrestore(&process_lock, flags);
	}
}

/*FIXME: This function is unnecessary for software breakpoints*/
/**
 * modify_user_sw_breakpoint - modify a user-space software breakpoint
 * @bp: the breakpoint structure to modify
 * @attr: new breakpoint attributes
 */
int modify_user_sw_breakpoint(struct perf_event *swbp, struct perf_event_attr *attr)
{
	int err = 0;

	/*
	 * modify_user_hw_breakpoint can be invoked with IRQs disabled and hence it
	 * will not be possible to raise IPIs that invoke __perf_event_disable.
	 * So call the function directly after making sure we are targeting the
	 * current task.
	 */
	if (irqs_disabled() && swbp->ctx && swbp->ctx->task == current)
		perf_event_disable_local(swbp);
	else
		perf_event_disable(swbp);

	if (!swbp->attr.disabled)
		perf_event_enable(swbp);

	return err;
}
EXPORT_SYMBOL_GPL(modify_user_sw_breakpoint);

/**
 * unregister_hw_breakpoint - unregister a user-space hardware breakpoint
 * @bp: the breakpoint structure to unregister
 */
void unregister_sw_breakpoint(struct perf_event *event)
{
	if (!event) return;
	perf_event_release_kernel(event);
}
EXPORT_SYMBOL_GPL(unregister_sw_breakpoint);

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
//	u64 start;
//	u64 end;

	if (val != DIE_INT3 ) return NOTIFY_DONE;

	if (regs) ip = regs->ip;

	/* only userspace traps */
	if (regs && !user_mode(regs))
		return NOTIFY_DONE;
//	start = ktime_get_ns();
	event = search_event_by_current(regs);
//	end = ktime_get_ns();
	if (!event) {
		//trace_printk("DIE_INT3: swbp not found pid:%d tid %d rip: 0x%lx bx 0x%lx in \n",pid, tid,  regs->ip, regs->bx);
		return ret;
	}

	tpid = task_tgid_nr(event->hw.target);
	ttid = task_pid_nr(event->hw.target);
	switch (val) {
	case DIE_INT3:
		trace_printk("swbp rip: 0x%lx bx 0x%lx in \n",regs->ip, regs->bx);
		preempt_disable();
		migrate_disable();
		perf_bp_event(event, regs);

		migrate_enable();
		preempt_enable();
		//trace_printk("swbp \n");
		ret = NOTIFY_STOP;
		break;
	default:
		break;
	}

	return ret;
}

static struct notifier_block sw_breakpoint_exceptions_nb = {
	.notifier_call = sw_breakpoint_exceptions_notify,
	/* we need to be notified first */
	.priority = 0x7fffffff
};

static int register_perf_sw_breakpoint(struct perf_event *event)
{
	if(!capable(CAP_SYS_ADMIN))
		return -EPERM;
	return 0;
}

static void *allocate_sw_breakpoint(struct perf_event *event, int irq)
{
	struct sw_bp_info *sw_item = NULL;
	struct task_struct *task = event->hw.target;
	if (irq)
		 sw_item = kzalloc(sizeof(struct sw_bp_info), GFP_ATOMIC);
	else
		 sw_item = kzalloc(sizeof(struct sw_bp_info), GFP_KERNEL);

	if (!sw_item) return NULL;

	sw_item->base_addr = event->attr.config1;
	sw_item->enc_addr  = event->attr.config2;
	sw_item->type	   = event->attr.bp_type;
	sw_item->event	   = event;
	sw_item->enabled   = 0;
	/*current is always owner of event*/
	sw_item->rid	   = task_tgid_nr(current);
	sw_item->pid	   = task_tgid_nr(task);
	sw_item->tid 	   = task_pid_nr(task);
	return sw_item;
}
static inline int add_sw_item(struct perf_event *event, struct thread_node *tnode , int irq)
{
	struct sw_bp_info *sw_item  = NULL;
	unsigned long flags;

	sw_item = (struct sw_bp_info *) allocate_sw_breakpoint(event, irq);
	if (sw_item == NULL)
		return -ENOMEM;
	sw_item->enabled = 1;

	if (irq) spin_lock(&tnode->lock);
	else spin_lock_irqsave(&tnode->lock, flags);

	list_add(&sw_item->list, &tnode->bp_list);
	INIT_LIST_HEAD(&event->hw.bp_list);
	list_add(&sw_item->event_list, &event->hw.bp_list);
	sw_item->parent_thread = tnode;
	if (irq) spin_unlock(&tnode->lock);
	else spin_unlock_irqrestore(&tnode->lock, flags);

	return 0;
}

static inline void kick_not_current_thread(struct perf_event *event)
{
	pid_t ctid = task_pid_nr(current);
	pid_t ttid = task_pid_nr(event->hw.target);

	if (ctid != ttid) {
		kick_process(event->hw.target);
	}
}
static int sw_breakpoint_event_init(struct perf_event *event)
{
	struct process_list *proc_list = NULL;
	unsigned long flags;
	int err;

	pid_t pid;

	if (event->attr.type != PERF_TYPE_SW_BREAKPOINT) {
		return -ENOENT;
	}

	if (!event->hw.target)
		return -EINVAL;

	/*
	 * no branch sampling for software breakpoint events
	 */
	if (has_branch_stack(event))
		return -EOPNOTSUPP;

	//err = register_perf_sw_breakpoint(event);
	//if (err)
	//	return err;

	pid = task_tgid_nr(event->hw.target);

	proc_list = get_process_list_pid(pid);
	if (!proc_list) {
		spin_lock_irqsave(&process_lock, flags);
		proc_list = kzalloc(sizeof(struct process_list), GFP_ATOMIC);

		if (!proc_list) {
			spin_unlock_irqrestore(&process_lock, flags);
			return -ENOMEM;
		}

		proc_list->pid = pid;
		atomic_set(&proc_list->count, 0);
		INIT_LIST_HEAD(&proc_list->thread_list);
		list_add(&proc_list->process_list, &per_process_list);
		spin_unlock_irqrestore(&process_lock, flags);
	}

	event->destroy = swbp_perf_event_destroy;
	return 0;
}
static struct thread_node *add_thread_node(struct process_list *list, pid_t tid)
{
	struct thread_node *node;

	node = kzalloc(sizeof(struct thread_node), GFP_ATOMIC);
	if (!node) return NULL;
	node->tid = tid;
	INIT_LIST_HEAD(&node->bp_list);
	spin_lock(&list->lock);
	list_add(&node->thread_list, &list->thread_list);
	node->parent_proc = list;
	spin_unlock(&list->lock);
	return node;
}

static int sw_breakpoint_add(struct perf_event *event, int flags)
{
	struct process_list *proc_list = NULL;
	struct thread_node *node = NULL;
	pid_t pid ;
	int ret = 0;
	pid_t tid;

	if (!event->hw.target)
		return -EINVAL;
	if (event->cpu > -1)
		return -EINVAL;

	pid = task_tgid_nr(event->hw.target);
	tid = task_pid_nr(event->hw.target);

	if (!(flags & PERF_EF_START))
		event->hw.state = PERF_HES_STOPPED;

	if (is_sampling_event(event)) {
		event->hw.last_period = event->hw.sample_period;
		perf_swevent_set_period(event);
	}

	if (event->hw.bp_list.next == 0) {
//   if ( !search_by_event(event, NULL, NULL) ) {
		spin_lock(&process_lock);
		proc_list = get_process_list_pid(pid);
		if (!proc_list){
			spin_unlock(&process_lock);
			 return -EINVAL;
		}
		node = _get_thread_list(proc_list, tid);
		spin_unlock(&process_lock);
		if (!node) {
			node = add_thread_node(proc_list, tid);
			if (!node) return -ENOMEM;
		}
		ret = add_sw_item(event, node, 1);
		if (ret == 0)
			atomic_inc(&proc_list->count);
	}

	//toggle_event(event, 1);
	kick_not_current_thread(event);
	return ret;
}

static void sw_breakpoint_del(struct perf_event *event, int flags)
{
	//toggle_event(event, 0);
}

static void sw_breakpoint_start(struct perf_event *event, int flags)
{
	/*does nothing*/
	//toggle_event(event, 1);
	event->hw.state = 0;
}

static void sw_breakpoint_stop(struct perf_event *event, int flags)
{
	//toggle_event(event, 1);
	event->hw.state = PERF_HES_STOPPED;
}

void sw_breakpoint_pmu_read(struct perf_event *event)
{
}

static struct pmu perf_sw_breakpoint = {
	.task_ctx_nr	= perf_sw_context, /* could eventually get its own */

	.event_init	= sw_breakpoint_event_init,
	.add		= sw_breakpoint_add,
	.del		= sw_breakpoint_del,
	.start		= sw_breakpoint_start,
	.stop		= sw_breakpoint_stop,
	.read		= sw_breakpoint_pmu_read,
};

int __init init_sw_breakpoint(void)
{
	perf_pmu_register(&perf_sw_breakpoint, "sw_breakpoint", PERF_TYPE_SW_BREAKPOINT);
	return register_die_notifier(&sw_breakpoint_exceptions_nb);
}


