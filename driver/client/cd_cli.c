/*
*/

#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/major.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/highmem.h>
#include <linux/mutex.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/cdrom.h>
#include <linux/workqueue.h>
#include <linux/timer.h>
#include <linux/cdev.h>

#include <asm/uaccess.h>


#include <cd_cli_cmd.h>
#include <cd_cli.h>
#include <klog.h>

MODULE_LICENSE("GPL");

#define __SUBCOMPONENT__ "cd_cli"
#define __LOGNAME__ "cd_cli.log"

#define SECTOR_SHIFT		9
#define PAGE_SECTORS_SHIFT	(PAGE_SHIFT - SECTOR_SHIFT)
#define PAGE_SECTORS		(1 << PAGE_SECTORS_SHIFT)


#define SECTOR_SIZE  (PAGE_SIZE/PAGE_SECTORS)


#define CBLOCK_SIZE (64*1024)

#define CBLOCK_SHIFT 16
#define CBLOCK_PAGES_SHIFT (CBLOCK_SHIFT - PAGE_SHIFT)
#define CBLOCK_SECTORS_SHIFT (CBLOCK_SHIFT - SECTOR_SHIFT) //7
#define CBLOCK_PAGES (CBLOCK_SIZE/PAGE_SIZE)
#define CBLOCK_SECTORS (CBLOCK_SIZE/SECTOR_SIZE)


#define CDISK_BLOCKS 1000

#define CDISK_FLAGS_CTL		(1 << 0)
#define CDISK_FLAGS_DELETING	(1 << 1)
#define CDISK_NUMS 256

#define CDISK_BLOCK_DEV_NAME	"cdisk"
#define CDISKCTL_CHAR_DEV_NAME 	"cdiskctl"

#define CDISK_TIMER_TIMEOUT_MSECS 20000

struct cdisk_block {
	void 			*data;
	int			size;
	atomic_t 		dirty;
	struct mutex 		mutex;
	spinlock_t		lock;
	unsigned long		off;
	unsigned long		idx;
	struct list_head 	blocks_list;
};

struct cdisk_device {
	int			number;
	int			flags;
	int			num_blocks;
	struct request_queue	*queue;
	struct gendisk		*disk;
	struct list_head	devices_list;

	spinlock_t		lock;
	int			blocks_count;
	struct cdisk_block	**blocks;
	atomic_t		writes;
	atomic_t		reads;
	atomic_t		write_bytes;
	atomic_t		read_bytes;
};


static struct workqueue_struct *cdisk_wq;

static struct timer_list cdisk_timer;

static int cdisk_num_alloc(void);
static void cdisk_num_free(int num);
static void cdisk_del_one(struct cdisk_device *device);
static struct cdisk_device *cdisk_alloc(int num);
static void cdisk_free(struct cdisk_device *device);

static char cdisk_nums[CDISK_NUMS];
static DEFINE_MUTEX(cdisk_nums_lock);

static DEFINE_MUTEX(cdisk_devices_lock);
static LIST_HEAD(cdisk_devices);

static int cdisk_block_major = -1;

static struct cdisk_block * cdisk_block_alloc(unsigned long block_idx)
{
	struct cdisk_block *block = kzalloc(sizeof(struct cdisk_block), GFP_KERNEL);
	if (!block)
		return NULL;

	memset(block, 0, sizeof(struct cdisk_block));
	atomic_set(&block->dirty, 0);
	mutex_init(&block->mutex);
	spin_lock_init(&block->lock);
	INIT_LIST_HEAD(&block->blocks_list);

	block->idx = block_idx;
	block->off = block_idx << CBLOCK_SHIFT;

	block->size = CBLOCK_SIZE;
	block->data = vmalloc(block->size);
	if (!block->data) 
		goto out;

	return block;
out:
	kfree(block);
	return NULL;
}

static void cdisk_block_free(struct cdisk_block *block)
{
	BUG_ON(!list_empty(&block->blocks_list));
	vfree(block->data);
	kfree(block);
}

static int cdisk_num_use(int num)
{
	int error = -EINVAL;
	
	if (num < 0 || num >= CDISK_NUMS)
		return -EINVAL;

	mutex_lock(&cdisk_nums_lock);
	if (cdisk_nums[num] == 0) {
		cdisk_nums[num] = 1;
		error = 0;
	} else {
		error = -EBUSY;
	}
	mutex_unlock(&cdisk_nums_lock);
	return error;
}

static int cdisk_num_alloc(void)
{
	int i = 0;
	int num = -1;

	mutex_lock(&cdisk_nums_lock);
	for (i = 0; i < CDISK_NUMS; i++) {
		if (cdisk_nums[i] == 0) {
			cdisk_nums[i] = 1;
			num = i;
			break;
		}
	}
	mutex_unlock(&cdisk_nums_lock);
	return num;
}

static void cdisk_num_free(int num) 
{
	if (num < 0 || num >= CDISK_NUMS)
		return;

	mutex_lock(&cdisk_nums_lock);
	cdisk_nums[num] = 0;
	mutex_unlock(&cdisk_nums_lock);	
}

static int cdisk_is_ctl(struct cdisk_device *device)
{
	return (device->flags & CDISK_FLAGS_CTL) ? 1 : 0;
}


static void *cdisk_lookup_sector(struct cdisk_device *device, sector_t sector)
{
	unsigned long block_idx;
	struct cdisk_block *block = NULL;

	block_idx = sector >> CBLOCK_SECTORS_SHIFT;
	
	BUG_ON(block_idx >= device->blocks_count);

	block = device->blocks[block_idx];
	if (!block)
		return NULL;

	BUG_ON(!block->data);
	return (void *)((unsigned long)block->data + ((sector - block_idx*CBLOCK_SECTORS) << SECTOR_SHIFT));		
}

static void cdisk_zero_sector(struct cdisk_device *device, sector_t sector)
{
	void *sec_addr = NULL;
	sec_addr = cdisk_lookup_sector(device, sector);
	if (!sec_addr)
		return;

	memset(sec_addr, 0, SECTOR_SIZE);
}

static void cdisk_zero_sector_bytes(struct cdisk_device *device, sector_t sector, size_t n)
{
	void *sec_addr = NULL;

	BUG_ON(n >= SECTOR_SIZE);
	sec_addr = cdisk_lookup_sector(device, sector);
	if (!sec_addr)
		return;

	memset(sec_addr, 0, n);
}

static void *cdisk_alloc_sector(struct cdisk_device *device, sector_t sector)
{
	unsigned long block_idx;
	void *sec_addr = NULL;

	sec_addr = cdisk_lookup_sector(device, sector);
	if (!sec_addr) {
		struct cdisk_block *block = NULL;
		block_idx = sector >> CBLOCK_SECTORS_SHIFT;
		BUG_ON(block_idx >= device->blocks_count);
		block = cdisk_block_alloc(block_idx);
		if (!block)
			return NULL;
		spin_lock(&device->lock);
		if (!device->blocks[block_idx]) {
			device->blocks[block_idx] = block;
			block = NULL;
		}
		spin_unlock(&device->lock);
		if (block)
			cdisk_block_free(block);
		sec_addr = cdisk_lookup_sector(device, sector);
	}

	return sec_addr;
}

static int cdisk_copy_to_setup(struct cdisk_device *device, sector_t sector,
	size_t n)
{	
	while (n >= SECTOR_SIZE) {
		if (!cdisk_alloc_sector(device, sector))
			return -ENOMEM;

		n-= SECTOR_SIZE;
		sector+= 1;
	};
	
	if (n) 
		if (!cdisk_alloc_sector(device, sector))
			return -ENOMEM;

	return 0;
}

static void cdisk_discard(struct cdisk_device *device, sector_t sector, size_t n)
{
	while (n >= SECTOR_SIZE) {
		cdisk_zero_sector(device, sector);
		n-= SECTOR_SIZE;
		sector+= 1;
	};
	
	if (n) 
		cdisk_zero_sector_bytes(device, sector, n);
	
}
//Copy n bytes from device at sector to dst
static void cdisk_copy_from(struct cdisk_device *device, void *dst, sector_t sector, size_t n)
{
	void *sec_addr = NULL;
	unsigned long off = 0;
	
	while (n >= SECTOR_SIZE) {
		sec_addr = cdisk_lookup_sector(device, sector);
		if (sec_addr)
			memcpy((void *)((unsigned long)dst + off), sec_addr, SECTOR_SIZE); 
		else
			memset((void *)((unsigned long)dst + off), 0, SECTOR_SIZE);

		off+= SECTOR_SIZE;
		n-= SECTOR_SIZE;
		sector+= 1;
	};
	//copy rest n bytes	
	if (n) { 
		sec_addr = cdisk_lookup_sector(device, sector);
		if (sec_addr)
			memcpy((void *)((unsigned long)dst + off), sec_addr, n); 
		else
			memset((void *)((unsigned long)dst + off), 0, n);
	}
}

//Copy n bytes from src to devices at sector 
static void cdisk_copy_to(struct cdisk_device *device, const void *src, sector_t sector, size_t n)
{
	void *sec_addr = NULL;
	unsigned long off = 0;
	
	while (n >= SECTOR_SIZE) {
		sec_addr = cdisk_lookup_sector(device, sector);
		BUG_ON(!sec_addr);
		memcpy(sec_addr, (void *)((unsigned long)src + off), SECTOR_SIZE); 
		off+= SECTOR_SIZE;
		n-= SECTOR_SIZE;
		sector+= 1;
	};
	//copy rest n bytes	
	if (n) { 
		sec_addr = cdisk_lookup_sector(device, sector);
		BUG_ON(!sec_addr);
		memcpy(sec_addr, (void *)((unsigned long)src + off), n); 
	}
}

static int cdisk_do_bvec(struct cdisk_device *device, struct page *page,
	unsigned int len, unsigned int off, int rw, sector_t sector)
{
	void *mem = NULL;
	int err = 0;
	if (rw != READ) {
		err = cdisk_copy_to_setup(device, sector, len);
		if (err)
			goto out;
	}
	mem = kmap_atomic(page);
	if (rw == READ) {
		cdisk_copy_from(device, (void *)((unsigned long)mem + off), sector, len);
		atomic_add(1, &device->reads);
		atomic_add(len, &device->read_bytes);
		flush_dcache_page(page);
	} else {
		flush_dcache_page(page);
		cdisk_copy_to(device, (void *)((unsigned long)mem + off), sector, len);
		atomic_add(1, &device->writes);
		atomic_add(len, &device->write_bytes);
	}
	kunmap_atomic(mem);
out:
	return err;
}


static void cdisk_make_request(struct request_queue *q, struct bio *bio)
{
	struct block_device *bdev = bio->bi_bdev;
	struct cdisk_device *device = bdev->bd_disk->private_data;
	int rw;
	struct bio_vec bvec;
	sector_t sector;
	struct bvec_iter iter;
	int err = -EIO;

	if (cdisk_is_ctl(device)) {
		//klog(KL_INFO, "device=%p is ctl device, so ignore I/O", device);
		err = -EIO;
		goto out;
	}
	
	sector = bio->bi_iter.bi_sector;
	if (bio_end_sector(bio) > get_capacity(bdev->bd_disk))
		goto out;

	if (unlikely(bio->bi_rw & REQ_DISCARD)) {
		err = 0;
		cdisk_discard(device, sector, bio->bi_iter.bi_size);
		goto out;
	}	
	rw = bio_rw(bio);
	if (rw == READA)
		rw = READ;

	bio_for_each_segment(bvec, bio, iter) {
		unsigned int len = bvec.bv_len;
		err = cdisk_do_bvec(device, bvec.bv_page, len,
			bvec.bv_offset, rw, sector);
		if (err)
			break;
		sector+= len >> SECTOR_SHIFT;
	}
out:
	bio_endio(bio, err);
}

static int cdisk_create(int num)
{
	struct cdisk_device *device = NULL;
	int error = -EINVAL;

	
	device = cdisk_alloc(num);
	if (!device) {
		error = -ENOMEM;
		goto out;
	}

	device->blocks_count = device->num_blocks;
	device->blocks = vmalloc(device->blocks_count*sizeof(struct cdisk_block *));
	if (!device->blocks) {
		error = -ENOMEM;
		goto free_device;
	}
	memset(device->blocks, 0, device->blocks_count*sizeof(struct cdisk_block *));

	klog(KL_INFO, "created device=%p, num=%d", device, device->number);

	mutex_lock(&cdisk_devices_lock);
	list_add_tail(&device->devices_list, &cdisk_devices);
	mutex_unlock(&cdisk_devices_lock);
	add_disk(device->disk);
	return 0;

free_device:
	cdisk_free(device);
out:
	return error;
}

static int cdisk_delete(int disk_num)
{
	int error = -EINVAL;
	struct cdisk_device *device = NULL;

	klog(KL_INFO, "disk_num=%d", disk_num);
	
	mutex_lock(&cdisk_devices_lock);
	list_for_each_entry(device, &cdisk_devices, devices_list) {
		if (device->number == disk_num) {
			cdisk_del_one(device);
			error = 0;			
			break;
		}	
	}
	mutex_unlock(&cdisk_devices_lock);

	return error;
}

static int cdisk_setup(int disk_num)
{
	int error = -EINVAL;

	klog(KL_ERR, "not implemented yet");
	return error;
}

static int cdisk_disk_ioctl(struct block_device *bdev, fmode_t mode, unsigned int cmd, unsigned long arg)
{
	int error = -EINVAL;
	struct cdisk_device *device = bdev->bd_disk->private_data;

	switch (cmd) {
		case BLKFLSBUF:
			klog(KL_INFO, "device=%p,  BLKFLSBUF", device);
			error = 0;
			break;
		case CDROM_GET_CAPABILITY:
			error = -ENOIOCTLCMD;
			break;
		default:
			error = -EINVAL;
			klog(KL_ERR, "%d not implemented yet, device=%p", cmd, device);
	}

	return error;
}

static const struct block_device_operations cdisk_fops = {
	.owner = THIS_MODULE,
	.ioctl = cdisk_disk_ioctl,
};

static void cdisk_del_one(struct cdisk_device *device)
{
	klog(KL_INFO, "deleting disk %p, num %d", device, device->number);

	list_del(&device->devices_list);
	del_gendisk(device->disk);
	cdisk_free(device);
	klog(KL_INFO, "deleted disk %p", device);
}

static struct cdisk_device *cdisk_alloc(int num)
{
	struct cdisk_device *device = NULL;
	struct gendisk *disk = NULL;
	
	if (num == -1) {
		num = cdisk_num_alloc();
		if (num == -1) 
			goto out;
	} else {
		if (cdisk_num_use(num))
			goto out;
	}

	device = kzalloc(sizeof(*device), GFP_KERNEL);
	if (!device)
		goto out_free_num;
	
	device->num_blocks = CDISK_BLOCKS;
	atomic_set(&device->reads, 0);
	atomic_set(&device->writes, 0);
	atomic_set(&device->read_bytes, 0);
	atomic_set(&device->write_bytes, 0);

	device->number = num;
	spin_lock_init(&device->lock);
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

	disk->major = cdisk_block_major;
	disk->first_minor = num;
	disk->fops = &cdisk_fops;
	disk->private_data = device;
	disk->queue = device->queue;
	disk->flags|= GENHD_FL_SUPPRESS_PARTITION_INFO;
	sprintf(disk->disk_name, "cdisk%d", num);
	set_capacity(disk, ((device->num_blocks*CBLOCK_SIZE)/SECTOR_SIZE));

	return device;

out_free_queue:
	blk_cleanup_queue(device->queue);
out_free_device:
	kfree(device);
out_free_num:
	cdisk_num_free(num);
out:
	return NULL;
}

static void cdisk_free_pages(struct cdisk_device *device)
{
	int i = 0;
	struct cdisk_block *block = NULL;

	for (i = 0; i < device->blocks_count; i++) {
		spin_lock(&device->lock);
		block = device->blocks[i];
		device->blocks[i] = NULL;
		spin_unlock(&device->lock);
		
		if (block)
			cdisk_block_free(block);
	}

	if (device->blocks) {
		vfree(device->blocks);
		device->blocks = NULL;
	}
}

static void cdisk_free(struct cdisk_device *device)
{
	put_disk(device->disk);
	blk_cleanup_queue(device->queue);
	cdisk_free_pages(device);
	cdisk_num_free(device->number);
	kfree(device);
}

static void cdisk_stats_log(struct cdisk_device *device)
{
	klog(KL_INFO, "dev=%p, num=%d, reads=%d, writes=%d, read_bytes=%d, write_bytes=%d", device, device->number,
		device->reads, device->writes, device->read_bytes, device->write_bytes);
}

static void cdisk_stats_work(struct work_struct *work)
{
	struct cdisk_device *device, *next;

	mutex_lock(&cdisk_devices_lock);

	list_for_each_entry_safe(device, next, &cdisk_devices, devices_list)
		cdisk_stats_log(device);

	mutex_unlock(&cdisk_devices_lock);

	kfree(work);
}
	
static void cdisk_timer_callback(unsigned long data)
{
	struct work_struct *work = NULL;

	klog(KL_INFO, "in timer");

	work = kmalloc(sizeof(struct work_struct), GFP_ATOMIC);
	if (!work)
		klog(KL_ERR, "cant alloc work");

	if (work) { 
		INIT_WORK(work, cdisk_stats_work);
		if (!queue_work(cdisk_wq, work)) {
			kfree(work);
			klog(KL_ERR, "cant queue work");
		}
	}
	mod_timer(&cdisk_timer, jiffies + msecs_to_jiffies(CDISK_TIMER_TIMEOUT_MSECS));
}

static int cdisk_char_open(struct inode *inode, struct file *file)
{
	klog(KL_INFO, "in open");
	if (!try_module_get(THIS_MODULE)) {
		klog(KL_ERR, "cant ref module");
		return -EINVAL;
	}
	klog(KL_INFO, "opened");
	return 0;
}

static int cdisk_char_release(struct inode *inode, struct file *file)
{
	klog(KL_INFO, "in release");
	module_put(THIS_MODULE);
	klog(KL_INFO, "released");
	return 0;
}

static long cdisk_char_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int error = -EINVAL;
	struct cdisk_ctl_params *params = NULL;	

	params = kmalloc(sizeof(struct cdisk_ctl_params), GFP_KERNEL);
	if (!params) {
		error = -ENOMEM;
		goto out;
	}

	if (copy_from_user(params, (const void *)arg, sizeof(struct cdisk_ctl_params))) {
		error = -EFAULT;
		goto out_free_params;
	}
	
	error = 0;
	switch (cmd) {
		case IOCTL_DISK_CREATE:
			params->error = cdisk_create(params->u.create.disk_num);	
			break;
		case IOCTL_DISK_DELETE:
			params->error = cdisk_delete(params->u.delete.disk_num);
			break;
		case IOCTL_DISK_SETUP:
			params->error = cdisk_setup(params->u.delete.disk_num);
			break;
		default:
			klog(KL_ERR, "unknown ioctl=%d", cmd);
			error = -EINVAL;
			break;
	}
	
	if (copy_to_user((void *)arg, params, sizeof(struct cdisk_ctl_params))) {
		error = -EFAULT;
		goto out_free_params;
	}
	
	return 0;
out_free_params:
	kfree(params);
out:
	return error;	
}

static struct file_operations cdiskctl_fops = {
	.owner = THIS_MODULE,
	.open = cdisk_char_open,
	.release = cdisk_char_release,
	.unlocked_ioctl = cdisk_char_ioctl
};


static struct class *cdiskctl_class;
static dev_t cdiskctl_dev_t;
static struct cdev cdiskctl_cdev;


#define CDISKCTL_MAX_MINOR 1

static int cdiskctl_create(void)
{
	int error = -EINVAL;
	struct device *device = NULL;


	cdiskctl_class = class_create(THIS_MODULE, CDISKCTL_CHAR_DEV_NAME);
	if (IS_ERR(cdiskctl_class)) {
		error = PTR_ERR(cdiskctl_class);
		klog(KL_ERR, "class_create error=%d", error);
		return error;
	}
	
	error = alloc_chrdev_region(&cdiskctl_dev_t, 0, CDISKCTL_MAX_MINOR, CDISKCTL_CHAR_DEV_NAME);
	if (error) {
		klog(KL_ERR, "alloc_chrdev_region failed err=%d", error);
		goto out_class_destroy;
	}
	cdev_init(&cdiskctl_cdev, &cdiskctl_fops);
	cdiskctl_cdev.owner = THIS_MODULE;

	error = cdev_add(&cdiskctl_cdev, cdiskctl_dev_t, CDISKCTL_MAX_MINOR);
	if (error) {
		klog(KL_ERR, "cdev_add failed with err=%d", error);
		goto out_unreg_devreg;
	}
	
	device = device_create(cdiskctl_class, NULL, MKDEV(MAJOR(cdiskctl_dev_t), 0), NULL, CDISKCTL_CHAR_DEV_NAME);
	if (IS_ERR(device)) {
		error = PTR_ERR(device);
		klog(KL_ERR, "device_create err=%d", error);
		goto out_cdev_del;
	}
	return 0;

out_cdev_del:
	cdev_del(&cdiskctl_cdev);
out_unreg_devreg:
	unregister_chrdev_region(cdiskctl_dev_t, CDISKCTL_MAX_MINOR);
out_class_destroy:
	class_destroy(cdiskctl_class);	
	return error;

}

static void cdiskctl_release(void)
{
	device_destroy(cdiskctl_class, MKDEV(MAJOR(cdiskctl_dev_t), 0));
	cdev_del(&cdiskctl_cdev);
	unregister_chrdev_region(cdiskctl_dev_t, CDISKCTL_MAX_MINOR);
	class_destroy(cdiskctl_class);
}

static int __init cdisk_init(void)
{	
	int error = -EINVAL;
	
	error = klog_init();
	if (error) {
		printk(KERN_ERR "klog_init failed with err=%d", error);
		goto out;
	}


	klog(KL_INFO, "init");
	
	error = cdiskctl_create();
	if (error) {
		klog(KL_ERR, "cdiskctl_create err=%d", error);
		goto out_log_release;
	}

	cdisk_block_major = register_blkdev(0, CDISK_BLOCK_DEV_NAME);
	if (cdisk_block_major < 0) {
		klog(KL_ERR, "register_blkdev failed, result=%d", cdisk_block_major);
		error = -ENOMEM;
		goto out_cdiskctl_release;
	}
	
	cdisk_wq = alloc_workqueue("cdisk-wq", WQ_MEM_RECLAIM|WQ_UNBOUND, 2);
	if (!cdisk_wq) {
		klog(KL_ERR, "cant create wq");
		error = -ENOMEM;
		goto out_unreg_block_dev;
	}

	setup_timer(&cdisk_timer, cdisk_timer_callback, 0);
	error = mod_timer(&cdisk_timer, jiffies + msecs_to_jiffies(CDISK_TIMER_TIMEOUT_MSECS));
	if (error) {
		klog(KL_ERR, "mod_timer failed with err=%d", error);
		goto out_del_wq;
	}	
	klog(KL_INFO, "module loaded, block major=%d", cdisk_block_major);
	return 0;

out_del_wq:
	destroy_workqueue(cdisk_wq);
out_unreg_block_dev:
	unregister_blkdev(cdisk_block_major, CDISK_BLOCK_DEV_NAME);
out_cdiskctl_release:
	cdiskctl_release();
out_log_release:
	klog_release();
out:
	return error;
}

static void __exit cdisk_exit(void)
{
	struct cdisk_device *device, *next;

	klog(KL_INFO, "exiting");

	del_timer_sync(&cdisk_timer);	
	destroy_workqueue(cdisk_wq);
	klog(KL_INFO, "going delete disks");

	mutex_lock(&cdisk_devices_lock);
	list_for_each_entry_safe(device, next, &cdisk_devices, devices_list)
		cdisk_del_one(device);
	mutex_unlock(&cdisk_devices_lock);

	unregister_blkdev(cdisk_block_major, CDISK_BLOCK_DEV_NAME);
	cdiskctl_release();

	klog(KL_INFO, "exited");
	klog_release();
}

module_init(cdisk_init);
module_exit(cdisk_exit);

