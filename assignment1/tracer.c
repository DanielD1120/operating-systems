// SPDX-License-Identifier: GPL-2.0+

/*
 * tracer.c - Kprobe based tracer
 *
 * Author: Daniel Dinca <dincadaniel97@gmail.com>
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/kprobes.h>
#include <linux/slab.h>
#include "tracer.h"

static struct miscdevice my_dev;
struct proc_dir_entry *proc_tracer_read;
DEFINE_SPINLOCK(process_list_lock);

struct process_info {
	pid_t pid;
	int nr_kmalloc;
	int nr_kfree;
	int nr_schedule;
	int nr_down_interruptible;
	int nr_up_interruptible;
	int nr_mutex_lock;
	int nr_mutex_unlock;
	unsigned long total_alocated_mem;
	unsigned long total_free_mem;
	spinlock_t increment_lock;
	spinlock_t mem_list_lock;
	struct list_head mem_list;
	struct list_head list;
};

struct allocated_mem {
	long mem_adr;
	long size;
	struct list_head list;
};

struct my_handler_data {
	long mem_addr;
	long size;
};

LIST_HEAD(process_list);

static int add_process_to_list(pid_t pid)
{
	struct process_info *next_elem =
			kcalloc(1, sizeof(*next_elem), GFP_KERNEL);

	if (!next_elem)
		return -ENOMEM;

	next_elem->pid = pid;
	INIT_LIST_HEAD(&next_elem->mem_list);
	spin_lock_init(&next_elem->increment_lock);
	spin_lock_init(&next_elem->mem_list_lock);

	spin_lock(&process_list_lock);
	list_add(&next_elem->list, &process_list);
	spin_unlock(&process_list_lock);

	return 0;
}

static void destroy_list_mem(struct list_head *my_list)
{
	struct list_head *i, *n;
	struct allocated_mem *elem;

	list_for_each_safe(i, n, my_list) {
		elem = list_entry(i, struct allocated_mem, list);
		list_del(i);
		kfree(elem);
	}
}

static void destroy_list_process(void)
{
	struct list_head *i, *n;
	struct process_info *elem;

	list_for_each_safe(i, n, &process_list) {
		elem = list_entry(i, struct process_info, list);
		list_del(i);
		destroy_list_mem(&elem->mem_list);
		kfree(elem);
	}
}

static int remove_process_from_list(pid_t pid)
{
	struct list_head *i, *tmp;
	struct process_info *elem;

	spin_lock(&process_list_lock);
	list_for_each_safe(i, tmp, &process_list) {
		elem = list_entry(i, struct process_info, list);
		if (elem->pid == pid) {
			list_del(i);
			destroy_list_mem(&elem->mem_list);
			kfree(elem);
			spin_unlock(&process_list_lock);
			return 0;
		}
	}
	spin_unlock(&process_list_lock);

	return -EINVAL;
}

static int tracer_proc_show(struct seq_file *m, void *v)
{
	struct list_head *i;
	struct process_info *elem;

	seq_puts(m, "PID kmalloc kfree kmalloc_mem kfree_mem sched up down lock unlock\n");

	list_for_each(i, &process_list) {
		elem = list_entry(i, struct process_info, list);
		seq_printf(m, "%d %d %d %lu %lu %d %d %d %d %d\n",
				  elem->pid,
				  elem->nr_kmalloc,
				  elem->nr_kfree,
				  elem->total_alocated_mem,
				  elem->total_free_mem,
				  elem->nr_schedule,
				  elem->nr_up_interruptible,
				  elem->nr_down_interruptible,
				  elem->nr_mutex_lock,
				  elem->nr_mutex_unlock);
	}

	return 0;
}

static int tracer_read_open(struct inode *inode, struct  file *file)
{
	return single_open(file, tracer_proc_show, NULL);
}

static int tracer_open(struct inode *inode, struct file *file)
{
	return 0;
}

static int tracer_release(struct inode *inode, struct file *file)
{
	return 0;
}

static long tracer_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int ret = 0;

	switch (cmd) {
	case TRACER_ADD_PROCESS:
		ret = add_process_to_list(arg);
		break;
	case TRACER_REMOVE_PROCESS:
		ret = remove_process_from_list(arg);
		break;
	default:
		ret = -EINVAL;
	}

	return ret;
}

static const struct file_operations my_fops = {
	.owner = THIS_MODULE,
	.open = tracer_open,
	.release = tracer_release,
	.unlocked_ioctl = tracer_ioctl,
};

static const struct file_operations r_fops = {
	.owner		= THIS_MODULE,
	.open		= tracer_read_open,
	.read		= seq_read,
	.release	= single_release,
};

static struct process_info *get_linked_list_elem(pid_t pid)
{
	struct list_head *i;
	struct process_info *elem;

	list_for_each(i, &process_list) {
		elem = list_entry(i, struct process_info, list);
		if (elem->pid == pid)
			return elem;
	}

	return NULL;
}

static void increment_counter(pid_t pid, int function)
{
	struct process_info *current_process = get_linked_list_elem(pid);

	spin_lock(&current_process->increment_lock);
	switch (function) {
	case 0:
		current_process->nr_kmalloc += 1;
		break;
	case 1:
		current_process->nr_kfree += 1;
		break;
	case 2:
		current_process->nr_schedule += 1;
		break;
	case 3:
		current_process->nr_up_interruptible += 1;
		break;
	case 4:
		current_process->nr_down_interruptible += 1;
		break;
	case 5:
		current_process->nr_mutex_lock += 1;
		break;
	case 6:
		current_process->nr_mutex_unlock += 1;
		break;
	default:
		break;
	}
	spin_unlock(&current_process->increment_lock);
}

static int add_allocated_mem(pid_t pid, struct my_handler_data hdata)
{
	struct allocated_mem *next_elem =
				kmalloc(sizeof(*next_elem), GFP_NOWAIT);
	struct process_info *current_process;

	if (!next_elem)
		return -ENOMEM;

	next_elem->mem_adr = hdata.mem_addr;
	next_elem->size = hdata.size;
	current_process = get_linked_list_elem(pid);

	current_process->total_alocated_mem += hdata.size;

	spin_lock(&current_process->mem_list_lock);
	list_add(&next_elem->list, &current_process->mem_list);
	spin_unlock(&current_process->mem_list_lock);

	return 0;
}

static int kmalloc_probe_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct my_handler_data *data = (struct my_handler_data *)ri->data;

	if (!get_linked_list_elem(current->pid))
		return -1;

	increment_counter(current->pid, 0);
	data->size = regs->ax;

	return 0;
}

static int kmalloc_probe_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct my_handler_data *data = (struct my_handler_data *)ri->data;
	int ret;

	data->mem_addr = regs_return_value(regs);

	if (get_linked_list_elem(current->pid)) {
		ret = add_allocated_mem(current->pid, *data);
		if (ret < 0) {
			pr_err("Failed to add allocated mem to list\n");
			return ret;
		}
	}

	return 0;
}

static struct kretprobe kmalloc_probe = {
	   .handler = kmalloc_probe_handler,
	   .entry_handler = kmalloc_probe_entry_handler,
	   .data_size = sizeof(struct my_handler_data),
	   .maxactive = 20,
};

static long get_size(struct process_info *current_process, long addr)
{
	struct list_head *i;
	struct allocated_mem *elem;
	struct list_head *my_list = &current_process->mem_list;

	list_for_each(i, my_list) {
		elem = list_entry(i, struct allocated_mem, list);
		if (elem->mem_adr == addr)
			return elem->size;
	}

	return -1;
}

static long get_size_for_free(pid_t pid, long addr)
{
	struct process_info *current_process = get_linked_list_elem(pid);

	if (!current_process)
		return -1;

	return get_size(current_process, addr);
}

static int kfree_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct process_info *current_process =
					get_linked_list_elem(current->pid);
	long addr;

	if (!current_process)
		return -1;

	addr = regs->ax;
	current_process->total_free_mem +=
			get_size_for_free(current->pid, addr);
	increment_counter(current->pid, 1);

	return 0;
}

static struct kretprobe kfree_probe = {
	   .entry_handler = kfree_handler,
	   .maxactive = 32,
};

static int schedule_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct process_info *current_process =
					get_linked_list_elem(current->pid);

	if (!current_process)
		return -1;

	increment_counter(current->pid, 2);

	return 0;
}

static struct kretprobe schedule_probe = {
	   .entry_handler = schedule_handler,
	   .maxactive = 32,
};

static int up_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct process_info *current_process =
					get_linked_list_elem(current->pid);

	if (!current_process)
		return -1;

	increment_counter(current->pid, 3);

	return 0;
}

static struct kretprobe up_probe = {
	   .entry_handler = up_handler,
	   .maxactive = 32,
};

static int down_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct process_info *current_process =
					get_linked_list_elem(current->pid);

	if (!current_process)
		return -1;

	increment_counter(current->pid, 4);

	return 0;
}

static struct kretprobe down_probe = {
	   .entry_handler = down_handler,
	   .maxactive = 32,
};

static int lock_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct process_info *current_process =
					get_linked_list_elem(current->pid);

	if (!current_process)
		return -1;

	increment_counter(current->pid, 5);

	return 0;
}

static struct kretprobe lock_probe = {
	   .entry_handler = lock_handler,
	   .maxactive = 32,
};

static int unlock_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct process_info *current_process =
					get_linked_list_elem(current->pid);

	if (!current_process)
		return -1;

	increment_counter(current->pid, 6);

	return 0;
}

static struct kretprobe unlock_probe = {
	   .entry_handler = unlock_handler,
	   .maxactive = 32,
};

static int tracer_init(void)
{
	int err;

	my_dev.minor = TRACER_DEV_MINOR;
	my_dev.name = TRACER_DEV_NAME;
	my_dev.fops = &my_fops;
	err = misc_register(&my_dev);
	if (err)
		goto out;

	proc_tracer_read = proc_create(TRACER_FILE_READ, 0000, NULL, &r_fops);
	if (!proc_tracer_read) {
		err = -ENOMEM;
		goto deregister_dev;
	}

	kmalloc_probe.kp.symbol_name = KMALLOC_FUNCTION;
	err = register_kretprobe(&kmalloc_probe);
	if (err < 0) {
		pr_err("register_kmalloc_probe failed, returned %d\n", err);
		goto remove_proc;
	}

	kfree_probe.kp.symbol_name = KFREE_FUNCTION;
	err = register_kretprobe(&kfree_probe);
	if (err < 0) {
		pr_err("register_kfree_probe failed, returned %d\n", err);
		goto unregister_kmalloc;
	}

	schedule_probe.kp.symbol_name = SCHEDULE_FUNCTION;
	err = register_kretprobe(&schedule_probe);
	if (err < 0) {
		pr_err("register_schedule_probe failed, returned %d\n", err);
		goto unregister_kfree;
	}

	up_probe.kp.symbol_name = UP_FUNCTION;
	err = register_kretprobe(&up_probe);
	if (err < 0) {
		pr_err("register_up_probe failed, returned %d\n", err);
		goto unregister_kschedule;
	}

	down_probe.kp.symbol_name = DOWN_FUNCTION;
	err = register_kretprobe(&down_probe);
	if (err < 0) {
		pr_err("register_down_probe failed, returned %d\n", err);
		goto unregister_kup;
	}

	lock_probe.kp.symbol_name = LOCK_FUNCTION;
	err = register_kretprobe(&lock_probe);
	if (err < 0) {
		pr_err("register_lock_probe failed, returned %d\n", err);
		goto unregister_kdown;
	}

	unlock_probe.kp.symbol_name = UNLOCK_FUNCTION;
	err = register_kretprobe(&unlock_probe);
	if (err < 0) {
		pr_err("register_unlock_probe failed, returned %d\n", err);
		goto unregister_lock;
	}

	return 0;

unregister_lock:
	unregister_kretprobe(&lock_probe);
unregister_kdown:
	unregister_kretprobe(&down_probe);
unregister_kup:
	unregister_kretprobe(&up_probe);
unregister_kschedule:
	unregister_kretprobe(&schedule_probe);
unregister_kfree:
	unregister_kretprobe(&kfree_probe);
unregister_kmalloc:
	unregister_kretprobe(&kmalloc_probe);
remove_proc:
	proc_remove(proc_tracer_read);
deregister_dev:
	misc_deregister(&my_dev);
out:
	return err;
}

static void tracer_exit(void)
{
	misc_deregister(&my_dev);
	proc_remove(proc_tracer_read);
	unregister_kretprobe(&kmalloc_probe);
	unregister_kretprobe(&kfree_probe);
	unregister_kretprobe(&schedule_probe);
	unregister_kretprobe(&up_probe);
	unregister_kretprobe(&down_probe);
	unregister_kretprobe(&lock_probe);
	unregister_kretprobe(&unlock_probe);
	destroy_list_process();
}

module_init(tracer_init);
module_exit(tracer_exit);

MODULE_DESCRIPTION("Kprobe based tracer");
MODULE_AUTHOR("Daniel Dinca <dincadaniel97@gmail.com>");
MODULE_LICENSE("GPL v2");
