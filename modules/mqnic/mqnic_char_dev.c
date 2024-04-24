#include "mqnic.h"

static struct class *g_mqnic_class;
#define MQ_NODE_NAME	"mqnic_char"
#define MQ_CHAR_DEV_COUNT 4


int char_open(struct inode *inode, struct file *file)
{
	struct mq_char_dev *char_dev;

	pr_notice("mqnic_char_device: char_open\n");

	/* pointer to containing structure of the character device inode */
	char_dev = container_of(inode->i_cdev, struct mq_char_dev, cdev);
	if (!char_dev) {
		pr_err("char_dev NULL\n");
		return -EINVAL;
	}

	pr_notice("mqnic_char_device: bar: 0x%llx size: 0x%llx", (uint64_t)char_dev->bar, char_dev->bar_size);
	pr_notice("mqnic_char_device: buf: 0x%llx size: 0x%lx", (uint64_t)char_dev->dev_buf, char_dev->dev_buf_size);

	/* create a reference to our char device in the opened file */
	file->private_data = char_dev;

	return 0;
}


/*
 * Called when the device goes from used to unused.
 */
int char_close(struct inode *inode, struct file *file)
{
	pr_notice("mqnic_char_device: char_close\n");

	return 0;
}

static ssize_t char_write(struct file *file, const char __user *buf, size_t count, loff_t *pos)
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
		copy_err = copy_from_user(&desc_data, &buf[buf_offset], sizeof(u32));
		if (!copy_err)
		{
			pr_notice("char_write 0x%x to 0x%llx", desc_data, *pos);
			mqnic_write_register(desc_data, base_addr + buf_offset);
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

static ssize_t char_read_log(struct file *file, char __user *buf,
                         size_t count, loff_t *pos)
{
	struct mq_char_dev *char_dev;
	int rc;
	int copy_err;
	char *base_addr;
	char *dev_buf_end;

	pr_notice("char_read_log: %lli:%li\n", *pos, count);

	if (!buf)
	{
		pr_err("char_read_log: Caught NULL pointer\n");
		return -EINVAL;
	}

	char_dev = (struct mq_char_dev *)file->private_data;
	dev_buf_end = (char*)char_dev->dev_buf + char_dev->dev_buf_size;
	base_addr = (char*)char_dev->dev_buf +  *pos;
	count = min_t(size_t, count, dev_buf_end - base_addr);
	rc = 0;
	if (count > 0)
	{
		copy_err = copy_to_user(buf, base_addr, count);
		if (!copy_err)
		{
			rc = count;
			*pos += count;
		}
		else
		{
			pr_err("char_read_log: Error writing data to userspace buffer\n");
			rc = -EINVAL;
		}
	}
	return rc;
}


static const struct file_operations ctrl_fops = {
		.owner = THIS_MODULE,
		.open = char_open,
		.release = char_close,
		.read = char_read,
		.write = char_write,
};

static const struct file_operations ctrl_log_fops = {
		.owner = THIS_MODULE,
		.open = char_open,
		.release = char_close,
		.read = char_read_log,
};

#define MQNIC_LOG_BUF_SIZE 16*1024*1024
struct mq_char_dev *create_mq_char_log_device(const char* name, int num)
{
	struct mq_char_dev *char_dev;
	int rv;
	dev_t dev;

	pr_notice("mqnic_char_device: create_mq_char_device %s", name);
	char_dev = kmalloc(sizeof(*char_dev), GFP_KERNEL);

	if (!char_dev)
		return NULL;
	memset(char_dev, 0, sizeof(*char_dev));

	char_dev->cdev.owner = THIS_MODULE;
	char_dev->bar = 0;
	char_dev->bar_size = 0;

	char_dev->dev_buf = vzalloc(MQNIC_LOG_BUF_SIZE);
	if (!char_dev->dev_buf)
		goto free_cdev;
	char_dev->dev_buf_size = MQNIC_LOG_BUF_SIZE;

	rv = kobject_set_name(&char_dev->cdev.kobj, name);

	if (rv)
	{
		pr_err("create_mq_char_device: kobject_set_name faied.\n");
		goto free_cdev;
	}

	if (num == 0)
	{
		rv = alloc_chrdev_region(&dev, 0, MQ_CHAR_DEV_COUNT, MQ_NODE_NAME);
		if (rv)
		{
			pr_err("create_mq_char_device: unable to allocate cdev region %d.\n", rv);
			goto free_cdev;
		}
	}

	cdev_init(&char_dev->cdev, &ctrl_log_fops);

	char_dev->major = MAJOR(dev);

	char_dev->cdevno = MKDEV(char_dev->major, MINOR(dev) + num);

	/* bring character device live */
	rv = cdev_add(&char_dev->cdev, char_dev->cdevno, 1);
	if (rv < 0) {
		pr_err("create_mq_char_device: cdev_add %s failed %d\n", name, rv);
		goto unregister_region;
	}

	char_dev->sys_device = device_create(g_mqnic_class, NULL, char_dev->cdevno, NULL, name);

	if (!char_dev->sys_device) {
		pr_err("create_mq_char_log_device: device_create(%s) failed\n", name);
		goto unregister_region;
	}


	pr_notice("create_mq_char_log_device %s succeeded", name);

	return char_dev;

unregister_region:
	unregister_chrdev_region(char_dev->cdevno, MQ_CHAR_DEV_COUNT);
free_cdev:
	if (char_dev->dev_buf)
	{
		vfree(char_dev->dev_buf);
		char_dev->dev_buf = 0;
	}
	kfree(char_dev);
	return NULL;
}

struct mq_char_dev *create_mq_char_device(const char* name, int num,
		u8 __iomem *hw_addr, resource_size_t hw_regs_size)
{
	struct mq_char_dev *char_dev;
	int rv;
	dev_t dev;

	pr_notice("mqnic_char_device: create_mq_char_device %s", name);
	char_dev = kmalloc(sizeof(*char_dev), GFP_KERNEL);

	if (!char_dev)
		return NULL;
	memset(char_dev, 0, sizeof(*char_dev));

	char_dev->cdev.owner = THIS_MODULE;
	char_dev->bar = hw_addr;
	char_dev->bar_size = hw_regs_size;
	char_dev->dev_buf = 0;
	char_dev->dev_buf_size = 0;

	rv = kobject_set_name(&char_dev->cdev.kobj, name);

	if (rv)
	{
		pr_err("create_mq_char_device: kobject_set_name faied.\n");
		goto free_cdev;
	}

	if (num == 0)
	{
		rv = alloc_chrdev_region(&dev, 0, MQ_CHAR_DEV_COUNT, MQ_NODE_NAME);
		if (rv)
		{
			pr_err("create_mq_char_device: unable to allocate cdev region %d.\n", rv);
			goto free_cdev;
		}
	}

	cdev_init(&char_dev->cdev, &ctrl_fops);

	char_dev->major = MAJOR(dev);

	char_dev->cdevno = MKDEV(char_dev->major, MINOR(dev) + num);

	/* bring character device live */
	rv = cdev_add(&char_dev->cdev, char_dev->cdevno, 1);
	if (rv < 0) {
		pr_err("create_mq_char_device: cdev_add %s failed %d\n", name, rv);
		goto unregister_region;
	}

	char_dev->sys_device = device_create(g_mqnic_class, NULL, char_dev->cdevno, NULL, name);

	if (!char_dev->sys_device) {
		pr_err("create_mq_char_device: device_create(%s) failed\n", name);
		goto unregister_region;
	}


	pr_notice("mqnic_char_device: create_mq_char_device %s succeeded", name);

	return char_dev;


unregister_region:
	unregister_chrdev_region(char_dev->cdevno, MQ_CHAR_DEV_COUNT);
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

	unregister_chrdev_region(MKDEV(char_dev->major, 0), MQ_CHAR_DEV_COUNT);
}

void mq_free_char_dev(struct mq_char_dev *char_dev)
{
	pr_notice("mqnic_char_device mq_free_char_dev");
	if (char_dev->dev_buf)
	{
		vfree(char_dev->dev_buf);
		char_dev->dev_buf = 0;
	}
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
