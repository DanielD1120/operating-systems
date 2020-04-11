// SPDX-License-Identifier: GPL-2.0+

/*
 * list.c - Linux kernel list API
 *
 * Author: Daniel Dinca <dincadaniel97@gmail.com>
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/string.h>

#define PROCFS_MAX_SIZE		512

#define procfs_dir_name		"list"
#define procfs_file_read	"preview"
#define procfs_file_write	"management"

struct proc_dir_entry *proc_list;
struct proc_dir_entry *proc_list_read;
struct proc_dir_entry *proc_list_write;

struct string_list {
	char *string;
	struct list_head list;
};

LIST_HEAD(my_list);

static int list_proc_show(struct seq_file *m, void *v)
{
	struct list_head *i;
	struct string_list *elem;

	list_for_each(i, &my_list) {
		elem = list_entry(i, struct string_list, list);
		seq_printf(m, "%s\n", elem->string);
	}

	return 0;
}

static int list_read_open(struct inode *inode, struct  file *file)
{
	return single_open(file, list_proc_show, NULL);
}

static int list_write_open(struct inode *inode, struct  file *file)
{
	return single_open(file, list_proc_show, NULL);
}

static int add_string(char *str, int pos)
{
	struct string_list *next_elem = kmalloc(sizeof(*next_elem), GFP_KERNEL);

	if (!next_elem)
		return -ENOMEM;

	next_elem->string = kmalloc(strlen(str), GFP_KERNEL);
	strcpy(next_elem->string, str);

	if (!pos)
		list_add(&next_elem->list, &my_list);
	else
		list_add_tail(&next_elem->list, &my_list);

	return 0;
}

static int delete_string(char *str)
{
	struct list_head *i, *tmp;
	struct string_list *elem;

	list_for_each_safe(i, tmp, &my_list) {
		elem = list_entry(i, struct string_list, list);
		if (strcmp(str, elem->string) == 0) {
			list_del(i);
			kfree(elem);
			return 0;
		}
	}

	return -EINVAL;
}

static int delete_all_string(char *str)
{
	struct list_head *i, *tmp;
	struct string_list *elem;

	list_for_each_safe(i, tmp, &my_list) {
		elem = list_entry(i, struct string_list, list);
		if (strcmp(str, elem->string) == 0) {
			list_del(i);
			kfree(elem);
		}
	}

	return 0;
}

static ssize_t list_write(struct file *file, const char __user *buffer,
			  size_t count, loff_t *offs)
{
	char local_buffer[PROCFS_MAX_SIZE];
	unsigned long local_buffer_size = 0;
	char command[5];
	char *str;
	char *str_pos;
	int err;

	local_buffer_size = count;
	if (local_buffer_size > PROCFS_MAX_SIZE)
		local_buffer_size = PROCFS_MAX_SIZE;

	memset(local_buffer, 0, PROCFS_MAX_SIZE);
	if (copy_from_user(local_buffer, buffer, local_buffer_size))
		return -EFAULT;

	/* local_buffer contains your command written in /proc/list/management
	 * TODO 4/0: parse the command and add/delete elements.
	 */

	err = sscanf(local_buffer, "%s", command);
	if (err == -1)
		return -1;
	str_pos = strstr(local_buffer, " ");
	if (str_pos	== NULL)
		return -1;
	str_pos += 1;
	str = kmalloc(strlen(str_pos) + 1, GFP_KERNEL);
	// delete the newline added from the echo command
	str_pos[strlen(str_pos) - 1] = '\0';
	strcpy(str, str_pos);

	if (strcmp(command, "addf") == 0)
		add_string(str, 0);
	else if (strcmp(command, "adde") == 0)
		add_string(str, 1);
	else if (strcmp(command, "delf") == 0)
		delete_string(str);
	else if (strcmp(command, "dela") == 0)
		delete_all_string(str);

	return local_buffer_size;
}

static const struct file_operations r_fops = {
	.owner		= THIS_MODULE,
	.open		= list_read_open,
	.read		= seq_read,
	.release	= single_release,
};

static const struct file_operations w_fops = {
	.owner		= THIS_MODULE,
	.open		= list_write_open,
	.write		= list_write,
	.release	= single_release,
};

static int list_init(void)
{
	proc_list = proc_mkdir(procfs_dir_name, NULL);
	if (!proc_list)
		return -ENOMEM;

	proc_list_read = proc_create(procfs_file_read, 0000, proc_list,
				     &r_fops);
	if (!proc_list_read)
		goto proc_list_cleanup;

	proc_list_write = proc_create(procfs_file_write, 0000, proc_list,
				      &w_fops);
	if (!proc_list_write)
		goto proc_list_read_cleanup;

	return 0;

proc_list_read_cleanup:
	proc_remove(proc_list_read);
proc_list_cleanup:
	proc_remove(proc_list);
	return -ENOMEM;
}

static void list_exit(void)
{
	proc_remove(proc_list);
}

module_init(list_init);
module_exit(list_exit);

MODULE_DESCRIPTION("Linux kernel list API");
MODULE_AUTHOR("Daniel Dinca <dincadaniel97@gmail.com>");
MODULE_LICENSE("GPL v2");
