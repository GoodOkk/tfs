/*
 * Ram backed block device driver.
 *
 * Copyright (C) 2007 Nick Piggin
 * Copyright (C) 2007 Novell Inc.
 *
 * Parts derived from drivers/block/rd.c, and drivers/block/loop.c, copyright
 * of their respective owners.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/major.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/highmem.h>
#include <linux/mutex.h>
#include <linux/radix-tree.h>
#include <linux/fs.h>
#include <linux/slab.h>

#include <asm/uaccess.h>

#include "klog.h"

#define __SUBCOMPONENT__ "cdisk"

#define SECTOR_SHIFT		9
#define PAGE_SECTORS_SHIFT	(PAGE_SHIFT - SECTOR_SHIFT)
#define PAGE_SECTORS		(1 << PAGE_SECTORS_SHIFT)

#define CDISK_IN_SECTORS_SIZE 100

struct cdisk_device {
	int		number;

	struct request_queue	*queue;
	struct gendisk		*disk;
	struct list_head	list_entry;

	/*
	 * Backing store of pages and lock to protect it. This is the contents
	 * of the block device.
	 */
	spinlock_t		lock;
	struct radix_tree_root	pages;
};

/*
 * Look up and return a brd's page for a given sector.
 */
static DEFINE_MUTEX(mutex);

static LIST_HEAD(cdisk_devices);

static int cdisk_major = -1;
#define CDISK_DEV_NAME "cdisk"


static void cdisk_make_request(struct request_queue *q, struct bio *bio)
{
	struct block_device *bdev = bio->bi_bdev;
	struct cdisk_device *device = bdev->bd_disk->private_data;
	int err = -EIO;

	klog(KL_INFO, "device=%p", device);

	bio_endio(bio, err);
}

static int cdisk_ioctl(struct block_device *bdev, fmode_t mode, unsigned int cmd, unsigned long arg)
{
	int error;
	struct cdisk_device *device = bdev->bd_disk->private_data;

	klog(KL_INFO, "ioctl=%d, device=%p", cmd, device);
	error = -EBUSY;
	return error;
}

static const struct block_device_operations cdisk_fops = {
	.owner = THIS_MODULE,
	.ioctl = cdisk_ioctl,
};

static struct cdisk_device *cdisk_alloc(int i)
{
	struct cdisk_device *device = NULL;
	struct gendisk *disk = NULL;

	device = kzalloc(sizeof(*device), GFP_KERNEL);
	if (!device)
		goto out;

	device->number = i;
	spin_lock_init(&device->lock);
	INIT_RADIX_TREE(&device->pages, GFP_ATOMIC);
	device->queue = blk_alloc_queue(GFP_KERNEL);
	if (!device->queue)
		goto out_free_device;

	blk_queue_make_request(device->queue, cdisk_make_request);
	blk_queue_max_hw_sectors(device->queue, 1024);
	blk_queue_bounce_limit(device->queue, BLK_BOUNCE_ANY);

	device->queue->limits.discard_granularity = PAGE_SIZE;
	device->queue->limits.max_discard_sectors = UINT_MAX;
	device->queue->limits.discard_zeroes_data = 1;
	queue_flag_set_unlocked(QUEUE_FLAG_DISCARD, device->queue);
	
	disk = device->disk = alloc_disk(1);
	if (!disk)
		goto out_free_queue;

	disk->major = cdisk_major;
	disk->first_minor = i;
	disk->fops = &cdisk_fops;
	disk->private_data = device;
	disk->queue = device->queue;
	disk->flags|= GENHD_FL_SUPPRESS_PARTITION_INFO;
	sprintf(disk->disk_name, "cdisk%d", i);
	set_capacity(disk, CDISK_IN_SECTORS_SIZE);

	return device;

out_free_queue:
	blk_cleanup_queue(device->queue);
out_free_device:
	kfree(device);
out:
	return NULL;
}

void cdisk_free_pages(struct cdisk_device *device)
{
	klog(KL_ERR, "not implemented yet");
}

static void cdisk_free(struct cdisk_device *device)
{
	put_disk(device->disk);
	blk_cleanup_queue(device->queue);
	cdisk_free_pages(device);
	kfree(device);
}

static int __init cdisk_init(void)
{	
	int major = -1;
	klog(KL_INFO, "init");	
	major = register_blkdev(0, CDISK_DEV_NAME);
	if (major < 0) {
		klog(KL_INFO, "register_blkdev failed, result=%d", major);
		return -EIO;
	}

	cdisk_major = major;
	klog(KL_INFO, "module loaded, major=%d", major);
	return 0;
}

static void __exit cdisk_exit(void)
{
	klog(KL_INFO, "exit");
	if (cdisk_major != -1) {
		unregister_blkdev(cdisk_major, CDISK_DEV_NAME);
		cdisk_major = -1;
	}
	klog(KL_INFO, "exited");
}

module_init(cdisk_init);
module_exit(cdisk_exit);
