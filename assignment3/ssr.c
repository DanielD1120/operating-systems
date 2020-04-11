// SPDX-License-Identifier: GPL-2.0+

/*
 * ssr.c - Software RAID
 *
 * Author: Daniel Dinca <dincadaniel97@gmail.com>
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/genhd.h>
#include <linux/fs.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/vmalloc.h>
#include <linux/sched.h>
#include <linux/crc32.h>
#include "ssr.h"

static struct my_block_dev {
	spinlock_t lock;
	struct request_queue *queue;
	struct gendisk *gd;
	size_t size;
} g_dev;

static struct block_device *phys_bdev1;
static struct block_device *phys_bdev2;

static struct workqueue_struct *my_workqueue;

struct my_bio_data {
	struct work_struct my_work;
	struct bio *bio;
};

static int my_block_open(struct block_device *bdev, fmode_t mode)
{
	return 0;
}

static void my_block_release(struct gendisk *gd, fmode_t mode)
{
}

static const struct block_device_operations my_block_ops = {
	.owner = THIS_MODULE,
	.open = my_block_open,
	.release = my_block_release
};

static void read_one_sector(struct gendisk *disk,
					int sector_number, char *buffer)
{
	struct bio *read_bio = bio_alloc(GFP_NOIO, 1);
	struct page *page = alloc_page(GFP_NOIO);
	char *buf;

	read_bio->bi_disk = disk;
	read_bio->bi_iter.bi_sector = sector_number;
	read_bio->bi_opf = READ;
	bio_add_page(read_bio, page, KERNEL_SECTOR_SIZE, 0);

	submit_bio_wait(read_bio);

	buf = kmap_atomic(page);
	memcpy(buffer, buf, KERNEL_SECTOR_SIZE);
	kunmap_atomic(buf);

	__free_page(page);
	bio_put(read_bio);
}

static void write_one_sector(struct gendisk *disk,
					int sector_number, char *buffer)
{
	struct bio *write_bio = bio_alloc(GFP_NOIO, 1);
	struct page *page = alloc_page(GFP_NOIO);
	char *buf;

	write_bio->bi_disk = disk;
	write_bio->bi_iter.bi_sector = sector_number;
	write_bio->bi_opf = WRITE;
	bio_add_page(write_bio, page, KERNEL_SECTOR_SIZE, 0);

	buf = kmap_atomic(page);
	memcpy(buf, buffer, KERNEL_SECTOR_SIZE);
	kunmap_atomic(buf);

	submit_bio_wait(write_bio);

	__free_page(page);
	bio_put(write_bio);
}

static void write_crc(struct gendisk *disk, struct bio *bio)
{
	int start_sector = bio->bi_iter.bi_sector;
	int nr_sectors = bio_sectors(bio);
	int i = start_sector;
	char *read_buffer = kmalloc(KERNEL_SECTOR_SIZE, GFP_KERNEL);
	char *crc_sector_buffer = kmalloc(KERNEL_SECTOR_SIZE, GFP_KERNEL);

	for (i = start_sector; i < start_sector + nr_sectors; i++) {
		u32 crc;
		int total_offset;
		int sector_for_crc;
		int offset_in_sector;

		memset(read_buffer, 0, KERNEL_SECTOR_SIZE);
		memset(crc_sector_buffer, 0, KERNEL_SECTOR_SIZE);

		/* read the sector */
		read_one_sector(disk, i, read_buffer);

		/* calculate crc value */
		crc = crc32(0, read_buffer, KERNEL_SECTOR_SIZE);

		/* get offset of crc */
		total_offset = LOGICAL_DISK_SIZE + i * sizeof(u32);
		sector_for_crc = total_offset / KERNEL_SECTOR_SIZE;
		offset_in_sector =
			total_offset - sector_for_crc * KERNEL_SECTOR_SIZE;

		/* get crc sector contents */
		read_one_sector(disk, sector_for_crc, crc_sector_buffer);

		/* write the crc at the correct position in buffer */
		memcpy(crc_sector_buffer + offset_in_sector, &crc, sizeof(u32));

		/* write the buffer in the crc sector */
		write_one_sector(disk, sector_for_crc, crc_sector_buffer);
	}

	kfree(read_buffer);
	kfree(crc_sector_buffer);
}

static u32 get_crc_for_sector(struct gendisk *disk, int sector)
{
	int total_offset, sector_for_crc, offset_in_sector;
	char *crc_sector_buffer = kmalloc(KERNEL_SECTOR_SIZE, GFP_KERNEL);
	u32 crc;

	total_offset = LOGICAL_DISK_SIZE + sector * sizeof(u32);
	sector_for_crc = total_offset / KERNEL_SECTOR_SIZE;
	offset_in_sector = total_offset - sector_for_crc * KERNEL_SECTOR_SIZE;

	read_one_sector(disk, sector_for_crc, crc_sector_buffer);
	memcpy(&crc, crc_sector_buffer + offset_in_sector, sizeof(u32));

	kfree(crc_sector_buffer);

	return crc;
}

static void solve_error(struct gendisk *disk, int sector, int correct_crc,
		char *correct_data, int stored_crc, int calc_crc)
{
	int total_offset;
	int sector_for_crc;
	int offset_in_sector;
	char *crc_sector_buffer = kmalloc(KERNEL_SECTOR_SIZE, GFP_KERNEL);

	/* if the stored crc is correct, rewrite sector */
	if (stored_crc == correct_crc) {
		write_one_sector(disk, sector, correct_data);
	/* if only the crc value is wrong */
	} else if (calc_crc == correct_crc) {
		total_offset = LOGICAL_DISK_SIZE + sector * sizeof(u32);
		sector_for_crc = total_offset / KERNEL_SECTOR_SIZE;
		offset_in_sector =
			total_offset - sector_for_crc * KERNEL_SECTOR_SIZE;

		read_one_sector(disk, sector_for_crc, crc_sector_buffer);
		memcpy(crc_sector_buffer + offset_in_sector,
				&correct_crc, sizeof(u32));
		write_one_sector(disk, sector_for_crc, crc_sector_buffer);
	}
}

static int check_crc(struct bio *bio)
{
	int start_sector = bio->bi_iter.bi_sector;
	int nr_sectors = bio_sectors(bio);
	int i = start_sector;
	char *read_buffer_1 = kmalloc(KERNEL_SECTOR_SIZE, GFP_KERNEL);
	char *read_buffer_2 = kmalloc(KERNEL_SECTOR_SIZE, GFP_KERNEL);

	for (i = start_sector; i < start_sector + nr_sectors; i++) {
		u32 crc_1, crc_2, crc_real_1, crc_real_2;

		memset(read_buffer_1, 0, KERNEL_SECTOR_SIZE);
		memset(read_buffer_2, 0, KERNEL_SECTOR_SIZE);

		crc_1 = get_crc_for_sector(phys_bdev1->bd_disk, i);
		read_one_sector(phys_bdev1->bd_disk, i, read_buffer_1);
		crc_real_1 = crc32(0, read_buffer_1, KERNEL_SECTOR_SIZE);

		crc_2 = get_crc_for_sector(phys_bdev2->bd_disk, i);
		read_one_sector(phys_bdev2->bd_disk, i, read_buffer_2);
		crc_real_2 = crc32(0, read_buffer_2, KERNEL_SECTOR_SIZE);

		if (crc_1 == crc_real_1) {
			if (crc_2 != crc_real_2) {
				solve_error(phys_bdev2->bd_disk, i, crc_1,
					read_buffer_1, crc_2, crc_real_2);
			}
		} else if (crc_2 == crc_real_2) {
			solve_error(phys_bdev1->bd_disk, i, crc_2,
				read_buffer_2, crc_1, crc_real_1);
		} else {
			kfree(read_buffer_1);
			kfree(read_buffer_2);
			return -1;
		}
	}

	kfree(read_buffer_1);
	kfree(read_buffer_2);

	return 0;
}

static void work_handler(struct work_struct *work)
{
	struct my_bio_data *my_bio =
				container_of(work, struct my_bio_data, my_work);
	struct bio *bio = my_bio->bio;
	struct bio_vec bvec;
	struct bvec_iter i;
	struct bio *bio1 = bio_alloc(GFP_NOIO, bio->bi_vcnt);
	struct bio *bio2 = bio_alloc(GFP_NOIO, bio->bi_vcnt);
	int dir = bio_data_dir(bio);

	bio1->bi_disk = phys_bdev1->bd_disk;
	bio1->bi_iter.bi_sector = bio->bi_iter.bi_sector;
	bio1->bi_opf = dir;

	bio2->bi_disk = phys_bdev2->bd_disk;
	bio2->bi_iter.bi_sector = bio->bi_iter.bi_sector;
	bio2->bi_opf = dir;

	bio_for_each_segment(bvec, bio, i) {
		bio_add_page(bio1, bvec.bv_page, bvec.bv_len, bvec.bv_offset);
		bio_add_page(bio2, bvec.bv_page, bvec.bv_len, bvec.bv_offset);
	}

	if (dir == WRITE) {
		submit_bio_wait(bio1);
		submit_bio_wait(bio2);
		write_crc(phys_bdev1->bd_disk, bio);
		write_crc(phys_bdev2->bd_disk, bio);
	} else {
		/* check and correct crc for every sector */
		if (check_crc(bio)) {
			bio_io_error(bio);
			bio_put(bio1);
			bio_put(bio2);
			return;
		}

		submit_bio_wait(bio1);
		submit_bio_wait(bio2);
	}

	bio_endio(bio);

	bio_put(bio1);
	bio_put(bio2);
}

blk_qc_t my_make_request(struct request_queue *q, struct bio *bio)
{
	struct my_bio_data *my_bio_struct;

	my_bio_struct = kmalloc(sizeof(struct my_bio_data), GFP_KERNEL);
	if (!my_bio_struct)
		return -ENOMEM;

	my_bio_struct->bio = bio;
	INIT_WORK(&my_bio_struct->my_work, work_handler);
	queue_work(my_workqueue, &my_bio_struct->my_work);

	return 0;
}

static int create_block_device(struct my_block_dev *dev)
{
	int err;

	dev->queue = blk_alloc_queue(GFP_KERNEL);
	if (dev->queue == NULL) {
		pr_err("cannot allocate block device queue\n");
		return -ENOMEM;
	}

	dev->size = LOGICAL_DISK_SIZE;
	blk_queue_make_request(dev->queue, my_make_request);
	dev->queue->queuedata = dev;

	dev->gd = alloc_disk(SSR_NUM_MINORS);
	if (!dev->gd) {
		pr_err("alloc_disk: failure\n");
		err = -ENOMEM;
		goto out_alloc_disk;
	}

	dev->gd->major = SSR_MAJOR;
	dev->gd->first_minor = SSR_FIRST_MINOR;
	dev->gd->fops = &my_block_ops;
	dev->gd->queue = dev->queue;
	dev->gd->private_data = dev;
	snprintf(dev->gd->disk_name, DISK_NAME_LEN, SSR_DEV_NAME);
	set_capacity(dev->gd, LOGICAL_DISK_SECTORS);

	add_disk(dev->gd);

	return 0;

out_alloc_disk:
	blk_cleanup_queue(dev->queue);
	return err;
}

static void delete_block_device(struct my_block_dev *dev)
{
	if (dev->gd) {
		del_gendisk(dev->gd);
		put_disk(dev->gd);
	}
	if (dev->queue)
		blk_cleanup_queue(dev->queue);
}

static struct block_device *open_disk(char *name)
{
	struct block_device *bdev;

	bdev = blkdev_get_by_path(name,
		FMODE_READ | FMODE_WRITE | FMODE_EXCL, THIS_MODULE);
	if (IS_ERR(bdev)) {
		pr_err("blkdev_get_by_path\n");
		return NULL;
	}

	return bdev;
}

static void close_disk(struct block_device *bdev)
{
	blkdev_put(bdev, FMODE_READ | FMODE_WRITE | FMODE_EXCL);
}

static int ssr_init(void)
{
	int err = 0;


	err = register_blkdev(SSR_MAJOR, SSR_DEV_NAME);
	if (err < 0) {
		pr_err("register_blkdev: unable to register\n");
		return err;
	}

	err = create_block_device(&g_dev);
	if (err < 0)
		goto out;

	phys_bdev1 = open_disk(PHYSICAL_DISK1_NAME);
	if (phys_bdev1 == NULL) {
		pr_err("[relay_init] No such device\n");
		err = -EINVAL;
		goto out1;
	}

	phys_bdev2 = open_disk(PHYSICAL_DISK2_NAME);
	if (phys_bdev2 == NULL) {
		pr_err("[relay_init] No such device\n");
		err = -EINVAL;
		goto out2;
	}

	my_workqueue = create_singlethread_workqueue("my_workqueue");

	return 0;

out2:
	close_disk(phys_bdev1);
out1:
	delete_block_device(&g_dev);
out:
	unregister_blkdev(SSR_MAJOR, SSR_DEV_NAME);
	return err;
}

static void ssr_exit(void)
{
	flush_workqueue(my_workqueue);
	destroy_workqueue(my_workqueue);
	delete_block_device(&g_dev);
	close_disk(phys_bdev1);
	close_disk(phys_bdev2);
	unregister_blkdev(SSR_MAJOR, SSR_DEV_NAME);
}

module_init(ssr_init);
module_exit(ssr_exit);

MODULE_DESCRIPTION("Software RAID");
MODULE_AUTHOR("Daniel Dinca <dincadaniel97@gmail.com>");
MODULE_LICENSE("GPL v2");
