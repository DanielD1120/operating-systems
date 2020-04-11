// SPDX-License-Identifier: GPL-2.0+

/*
 * uart16550.c - driver UART
 *
 * Author: Daniel Dinca <dincadaniel97@gmail.com>
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/uaccess.h>
#include <linux/interrupt.h>
#include <linux/spinlock.h>
#include <linux/kfifo.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include "uart16550.h"

int major = 42;
int option = OPTION_BOTH;
int device_number;

module_param(major, int, 0);
module_param(option, int, 0);

struct my_dev {
	struct cdev cdev;
	int base_port;
	int irq_no;
	DECLARE_KFIFO(read_buffer, char, FIFO_SIZE);
	DECLARE_KFIFO(write_buffer, char, FIFO_SIZE);
	wait_queue_head_t wq_reads, wq_writes;
	spinlock_t read_lock, write_lock;
};

struct my_dev devs[2];

irqreturn_t handler(int irq_no, void *dev_id)
{
	struct my_dev *my_data = (struct my_dev *) dev_id;
	int baseport = my_data->base_port;

	unsigned char interrupt_mask = 15;
	unsigned char interupts_identification = inb(baseport + 2);
	unsigned char current_interrupt = interrupt_mask
						& interupts_identification;

	if (current_interrupt == 4 || current_interrupt == 12) {
		unsigned char read_character = inb(baseport);

		kfifo_in_spinlocked(&my_data->read_buffer, &read_character,
							1, &my_data->read_lock);

		if (kfifo_is_full(&my_data->read_buffer)) {
			unsigned char current_interupts = inb(baseport + 1);

			outb(current_interupts & 0xfe, baseport + 1);
		}

		wake_up(&my_data->wq_reads);
	} else if (current_interrupt == 2) {
		unsigned char write_char = 0;

		kfifo_out_spinlocked(&my_data->write_buffer,
				&write_char, 1, &my_data->write_lock);
		outb(write_char, baseport);

		if (kfifo_is_empty(&my_data->write_buffer)) {
			unsigned char current_interupts = inb(baseport + 1);

			outb(current_interupts & 0xfd, baseport + 1);
		}

		wake_up(&my_data->wq_writes);
	} else {
		return IRQ_NONE;
	}

	return IRQ_HANDLED;
}

static int usart_open(struct inode *inode, struct file *file)
{
	struct my_dev *dev =
		container_of(inode->i_cdev, struct my_dev, cdev);

	file->private_data = dev;

	return 0;
}

static int usart_close(struct inode *inode, struct file *file)
{
	return 0;
}

static int usart_read(struct file *file, char *user_buffer,
	size_t size, loff_t *offset)
{
	struct my_dev *dev = (struct my_dev *)file->private_data;
	unsigned int copied_bytes;
	int baseport = dev->base_port;
	int to_read;
	int activate_interupts;
	unsigned char current_interupts;

	if (wait_event_interruptible(dev->wq_reads,
			kfifo_len(&dev->read_buffer) > 0))
		return -ERESTARTSYS;

	to_read = (size > kfifo_len(&dev->read_buffer)) ?
		kfifo_len(&dev->read_buffer) : size;
	activate_interupts = kfifo_len(&dev->read_buffer) == FIFO_SIZE ? 1 : 0;

	kfifo_to_user(&dev->read_buffer, user_buffer, to_read, &copied_bytes);

	if (activate_interupts) {
		current_interupts = inb(baseport + 1);
		outb(current_interupts | 0x1, baseport + 1);
	}

	return to_read;
}


static int usart_write(struct file *file, const char *user_buffer,
	size_t size, loff_t *offset)
{
	struct my_dev *dev = (struct my_dev *)file->private_data;
	int was_empty = kfifo_is_empty(&dev->write_buffer);
	int baseport = dev->base_port;
	unsigned int bytes_copied;
	int to_write;
	unsigned char current_interupts;

	if (wait_event_interruptible(dev->wq_writes,
			kfifo_is_full(&dev->write_buffer) == 0))
		return -ERESTARTSYS;

	to_write = (size > kfifo_avail(&dev->write_buffer)) ?
				kfifo_avail(&dev->write_buffer) : size;

	kfifo_from_user(&dev->write_buffer,
			user_buffer, to_write, &bytes_copied);

	if (was_empty) {
		current_interupts = inb(baseport + 1);
		outb(current_interupts | 0x2, baseport + 1);
	}

	return to_write;
}

static long usart_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int ret = 0;
	struct my_dev *dev = (struct my_dev *)file->private_data;
	int base_port = dev->base_port;
	int lcr = base_port + 3;
	int dll = base_port;
	unsigned char len_parity_stop;
	struct uart16550_line_info line_info;

	switch (cmd) {
	case UART16550_IOCTL_SET_LINE:
		ret = copy_from_user(&line_info,
				(void *)arg, sizeof(line_info));
		if (ret)
			return -EINVAL;
		len_parity_stop =
			line_info.len | line_info.par | line_info.stop;
		outb(len_parity_stop | 0x80, lcr);
		outb(line_info.baud, dll);
		outb(len_parity_stop, lcr);
		break;
	default:
		ret = -EINVAL;
	}

	return ret;
}

static const struct file_operations uart_fops = {
	.owner = THIS_MODULE,
	.open = usart_open,
	.release = usart_close,
	.read = usart_read,
	.write = usart_write,
	.unlocked_ioctl = usart_ioctl,
};

static int uart_init(void)
{
	int i, err;
	int base_port, ier, mcr;
	int region_to_free;

	switch (option) {
	case OPTION_COM1:
		err = register_chrdev_region(MKDEV(major, MINOR_COM1),
								1, MODULE_NAME);
		if (err != 0) {
			pr_info("register_chrdev_region");
			goto return_err;
		}
		if (!request_region(BASEPORT_COM1, 8, MODULE_NAME)) {
			err = -ENODEV;
			goto unregister_com;
		}
		device_number = 1;
		devs[0].base_port = BASEPORT_COM1;
		devs[0].irq_no = IRQ_COM1;
		break;
	case OPTION_COM2:
		err = register_chrdev_region(MKDEV(major, MINOR_COM2),
							1, MODULE_NAME);
		if (err != 0) {
			pr_info("register_chrdev_region");
			goto return_err;
		}
		if (!request_region(BASEPORT_COM2, 8, MODULE_NAME)) {
			err = -ENODEV;
			goto unregister_com;
		}
		device_number = 1;
		devs[0].base_port = BASEPORT_COM2;
		devs[0].irq_no = IRQ_COM2;
		break;
	case OPTION_BOTH:
		err = register_chrdev_region(MKDEV(major, MINOR_COM1),
							2, MODULE_NAME);
		if (err != 0) {
			pr_info("register_chrdev_region");
			goto return_err;
		}
		if (!request_region(BASEPORT_COM1, 8, MODULE_NAME)) {
			err = -ENODEV;
			goto unregister_com;
		}
		if (!request_region(BASEPORT_COM2, 8, MODULE_NAME)) {
			err = -ENODEV;
			region_to_free = 0;
			goto free_regions;
		}
		device_number = 2;
		devs[0].base_port = BASEPORT_COM1;
		devs[1].base_port = BASEPORT_COM2;
		devs[0].irq_no = IRQ_COM1;
		devs[1].irq_no = IRQ_COM2;
		break;
	default:
		break;
	}

	for (i = 0; i < device_number; i++) {
		err = request_irq(devs[i].irq_no,
				handler, IRQF_SHARED,
				MODULE_NAME, &devs[i]);
		if (err < 0) {
			if (device_number == 1) {
				region_to_free =
					devs[i].base_port == BASEPORT_COM1 ?
					0 : 1;
				goto free_regions;
			} else {
				if (i == 1) {
					free_irq(devs[0].irq_no, &devs[0]);
					region_to_free = 2;
					goto free_regions;
				} else {
					region_to_free = 2;
					goto free_regions;
				}
			}
		}

		INIT_KFIFO(devs[i].read_buffer);
		spin_lock_init(&devs[i].read_lock);
		init_waitqueue_head(&devs[i].wq_reads);
		INIT_KFIFO(devs[i].write_buffer);
		spin_lock_init(&devs[i].write_lock);
		init_waitqueue_head(&devs[i].wq_writes);

		base_port = devs[i].base_port;
		ier = base_port + 1;
		mcr = base_port + 4;
		/* activate rdai and global interrupts */
		outb(1, ier);
		outb(8, mcr);

		cdev_init(&devs[i].cdev, &uart_fops);
		cdev_add(&devs[i].cdev,
			MKDEV(major, i +
			(devs[0].base_port == BASEPORT_COM1 ? 0 : 1)),
			1);
	}

	return 0;

free_regions:
	switch (region_to_free) {
	case 0:
		release_region(BASEPORT_COM1, 8);
		break;
	case 1:
		release_region(BASEPORT_COM2, 8);
		break;
	case 2:
		release_region(BASEPORT_COM1, 8);
		release_region(BASEPORT_COM2, 8);
		break;
	default:
		break;
	}

unregister_com:
	switch (option) {
	case OPTION_COM1:
		unregister_chrdev_region(MKDEV(major, MINOR_COM1), 1);
		break;
	case OPTION_COM2:
		unregister_chrdev_region(MKDEV(major, MINOR_COM2), 1);
		break;
	case OPTION_BOTH:
		unregister_chrdev_region(MKDEV(major, MINOR_COM1), 2);
		break;
	default:
		break;
	}

return_err:
	return err;
}

static void uart_exit(void)
{
	int i;

	for (i = 0; i < device_number; i++) {
		cdev_del(&devs[i].cdev);
		kfifo_free(&devs[i].read_buffer);
		kfifo_free(&devs[i].write_buffer);
		free_irq(devs[i].irq_no, &devs[i]);
	}

	switch (option) {
	case OPTION_COM1:
		unregister_chrdev_region(MKDEV(major, MINOR_COM1), 1);
		release_region(BASEPORT_COM1, 8);
		break;
	case OPTION_COM2:
		unregister_chrdev_region(MKDEV(major, MINOR_COM2), 1);
		release_region(BASEPORT_COM2, 8);
		break;
	case OPTION_BOTH:
		unregister_chrdev_region(MKDEV(major, MINOR_COM1), 2);
		release_region(BASEPORT_COM1, 8);
		release_region(BASEPORT_COM2, 8);
		break;
	default:
		break;
	}

}

module_init(uart_init);
module_exit(uart_exit);

MODULE_DESCRIPTION("uart16550 driver");
MODULE_AUTHOR("Daniel Dinca <dincadaniel97@gmail.com>");
MODULE_LICENSE("GPL v2");
