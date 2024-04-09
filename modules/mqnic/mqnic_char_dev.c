#include "mqnic.h"

static struct class *g_mqnic_class;
#define MQ_NODE_NAME	"mqnicreg"
#define MQ_CHAR_DEV_NAME	"mqnic_reg"


int char_open(struct inode *inode, struct file *file)
{
	struct mq_char_dev *char_dev;

	pr_notice("mqnic_char_device: char_open");

	/* pointer to containing structure of the character device inode */
	char_dev = container_of(inode->i_cdev, struct mq_char_dev, cdev);
	if (!char_dev) {
		pr_err("char_dev NULL\n");
		return -EINVAL;
	}

	pr_notice("mqnic_char_device: bar: 0x%llx size: 0x%llx", (uint64_t)char_dev->bar, char_dev->bar_size);

	/* create a reference to our char device in the opened file */
	file->private_data = char_dev;

	return 0;
}


/*
 * Called when the device goes from used to unused.
 */
int char_close(struct inode *inode, struct file *file)
{
	pr_notice("mqnic_char_device: char_close");

	return 0;
}

static ssize_t char_write(struct file *file, const char __user *buf,
                                 size_t count, loff_t *pos)
{
	struct mq_char_dev *char_dev;
	u32 desc_data;
	size_t buf_offset;
	int rc;
	int copy_err;
	u8 __iomem *base_addr;

	pr_notice("mqnic_char_device: char_write %lli:%li", *pos, count);

	if (count & 3) {
		pr_err("mqnic_char_device: Buffer size must be a multiple of 4 bytes\n");
		return -EINVAL;
	}

	if (!buf) {
		pr_err("mqnic_char_device: Caught NULL pointer\n");
		return -EINVAL;
	}

	if (*pos & 3) {
		pr_err("mqnic_char_device: address must be a multiple of 4 bytes\n");
		return -EINVAL;
	}

	char_dev = (struct mq_char_dev *)file->private_data;

	if (*pos + sizeof(u32) * count > char_dev->bar_size)
	{
		pr_err("mqnic_char_device: char_read requested memory out of bar\n");
		return -EFAULT;
	}

	buf_offset = 0;
	base_addr = char_dev->bar + *pos;
	while (buf_offset < count) {
		copy_err = copy_from_user(&desc_data, &buf[buf_offset],
		                          sizeof(u32));
		if (!copy_err)
		{
			iowrite32(desc_data, base_addr + buf_offset);
			buf_offset += sizeof(u32);
			rc = buf_offset;
		}
		else
		{
			pr_err("mqnic_char_device: Error reading data from userspace buffer\n");
			rc = -EINVAL;
			break;
		}
	}

	return rc;
}

static ssize_t char_read(struct file *file, char __user *buf,
                                size_t count, loff_t *pos)
{
	struct mq_char_dev *char_dev;
	u32 desc_data;
	size_t buf_offset;
	int rc;
	int copy_err;
	u8 __iomem *base_addr;

	pr_notice("mqnic_char_device: char_read %lli:%li", *pos, count);

	if (count & 3)
	{
		pr_err("mqnic_char_device: Buffer size must be a multiple of 4 bytes\n");
		return -EINVAL;
	}

	if (!buf)
	{
		pr_err("mqnic_char_device: Caught NULL pointer\n");
		return -EINVAL;
	}

	if (*pos & 3) {
		pr_err("mqnic_char_device: address must be a multiple of 4 bytes\n");
		return -EINVAL;
	}

	char_dev = (struct mq_char_dev *)file->private_data;

	if (*pos + sizeof(u32) * count > char_dev->bar_size)
	{
		pr_err("mqnic_char_device: char_read requested memory out of bar\n");
		return -EFAULT;
	}

	buf_offset = 0;
	base_addr = char_dev->bar + *pos;
	while (buf_offset < count)
	{
		desc_data = ioread32(base_addr + buf_offset);
		copy_err = copy_to_user(&buf[buf_offset], &desc_data, sizeof(u32));
		if (!copy_err)
		{
			buf_offset += sizeof(u32);
			rc = buf_offset;
		}
		else
		{
			pr_err("mqnic_char_device: Error writing data to userspace buffer\n");
			rc = -EINVAL;
			break;
		}

		if (rc < 0)
			break;
	}
	return rc;
}


static const struct file_operations ctrl_fops = {
		.owner = THIS_MODULE,
		.open = char_open,
		.release = char_close,
		.read = char_read,
		.write = char_write,
		//.unlocked_ioctl = char_ctrl_ioctl,
};

struct mq_char_dev *create_mq_char_device(struct mqnic_dev *mq_dev)
{
	struct mq_char_dev *char_dev;
	int rv;
	dev_t dev;

	pr_notice("mqnic_char_device: create_mq_char_device");
	char_dev = kmalloc(sizeof(*char_dev   ), GFP_KERNEL);

	if (!char_dev)
		return NULL;
	memset(char_dev, 0, sizeof(*char_dev));

	char_dev->cdev.owner = THIS_MODULE;
	char_dev->bar = mq_dev->hw_addr;
	char_dev->bar_size = mq_dev->hw_regs_size;

	rv = kobject_set_name(&char_dev->cdev.kobj, MQ_CHAR_DEV_NAME);

	if (rv)
	{
		pr_err("create_mq_char_device: kobject_set_name faied.\n");
		goto free_cdev;
	}

	rv = alloc_chrdev_region(&dev, 0, 1, "mq");

	if (rv) {
		pr_err("create_mq_char_device: unable to allocate cdev region %d.\n", rv);
		goto free_cdev;
	}

	cdev_init(&char_dev->cdev, &ctrl_fops);

	char_dev->major = MAJOR(dev);

	char_dev->cdevno = MKDEV(char_dev->major, MINOR(dev) + 0);

	/* bring character device live */
	rv = cdev_add(&char_dev->cdev, char_dev->cdevno, 1);
	if (rv < 0) {
		pr_err("create_mq_char_device: cdev_add failed %d\n", rv);
		goto unregister_region;
	}

	char_dev->sys_device = device_create(g_mqnic_class, NULL, char_dev->cdevno, NULL, MQ_CHAR_DEV_NAME);

	pr_notice("mqnic_char_device: device_create %s succeeded", MQ_CHAR_DEV_NAME);

	if (!char_dev->sys_device) {
		pr_err("create_mq_char_device: device_create(%s) failed\n", MQ_CHAR_DEV_NAME);
		goto unregister_region;
	}


	pr_notice("mqnic_char_device: create_mq_char_device succeeded");

	return char_dev;

//del_cdev:
//	cdev_del(&char_dev->cdev);
unregister_region:
	unregister_chrdev_region(char_dev->cdevno, 1);
free_cdev:
	kfree(char_dev);
	return NULL;
}


void destroy_mq_char_device(struct mq_char_dev *char_dev)
{
	pr_notice("mqnic_char_device: destroy_mq_char_device");
	if (!char_dev)
	{
		pr_err("destroy_mq_char_device: char_dev is empty");
		return;
	}

	if (char_dev->sys_device)
		device_destroy(g_mqnic_class, char_dev->cdevno);
	cdev_del(&char_dev->cdev);

	unregister_chrdev_region(MKDEV(char_dev->major, 0), 1);
}

void mq_free_char_dev(struct mq_char_dev *char_dev)
{
	pr_notice("mqnic_char_device mq_free_char_dev");
	destroy_mq_char_device(char_dev);
	kfree(char_dev);
}


int mq_cdev_init(void)
{
	g_mqnic_class = class_create(THIS_MODULE, MQ_NODE_NAME);
	if (IS_ERR(g_mqnic_class)) {
		pr_err("mq_cdev_init: failed to create class %s", MQ_NODE_NAME);
		return -EINVAL;
	}

	/* using kmem_cache_create to enable sequential cleanup */
/*	cdev_cache = kmem_cache_create("cdev_cache",
	                               sizeof(struct cdev_async_io), 0,
	                               SLAB_HWCACHE_ALIGN, NULL);

	if (!cdev_cache) {
		pr_info("memory allocation for cdev_cache failed. OOM\n");
		return -ENOMEM;
	}*/

	pr_notice("mqnic_char_device: mq_cdev_init finished");

	return 0;
}

void mqnic_cdev_cleanup(void)
{
/*	if (cdev_cache)
		kmem_cache_destroy(cdev_cache);*/

	if (g_mqnic_class)
		class_destroy(g_mqnic_class);

	pr_notice("mqnic_char_device: mqnic_cdev_cleanup finished");
}
