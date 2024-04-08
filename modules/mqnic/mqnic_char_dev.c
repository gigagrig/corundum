#include "mqnic.h"


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
	/* create a reference to our char device in the opened file */
	file->private_data = char_dev;

	return 0;
}


#define IOCTL_XDMA_ADDRMODE_SET	_IOW('q', 4, int)
#define IOCTL_XDMA_ADDRMODE_GET	_IOR('q', 5, int)
#define IOCTL_XDMA_ALIGN_GET	_IOR('q', 6, int)

long char_ctrl_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
/*	struct mq_char_dev *char_dev;
	long result = 0;
	int rv;*/

	pr_notice("mqnic_char_device: char_ctrl_ioctl");

/*	switch (cmd) {
		case XDMA_IOCINFO:
			if (copy_from_user((void *)&ioctl_obj, (void __user *) arg,
			                   sizeof(struct xdma_ioc_base))) {
				pr_err("copy_from_user failed.\n");
				return -EFAULT;
			}

			if (ioctl_obj.magic != XDMA_XCL_MAGIC) {
				pr_err("magic 0x%x !=  XDMA_XCL_MAGIC (0x%x).\n",
				       ioctl_obj.magic, XDMA_XCL_MAGIC);
				return -ENOTTY;
			}
			return version_ioctl(xcdev, (void __user *)arg);
		case XDMA_IOCOFFLINE:
			xdma_device_offline(xdev->pdev, xdev);
			break;
		case XDMA_IOCONLINE:
			xdma_device_online(xdev->pdev, xdev);
			break;
		default:
			pr_err("UNKNOWN ioctl cmd 0x%x.\n", cmd);
			return -ENOTTY;
	}*/
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
	size_t buf_offset = 0;
	int rc = 0;
	int copy_err;

	pr_notice("mqnic_char_device: char_write");

	if (count & 3) {
		pr_err("mqnic_char_device: Buffer size must be a multiple of 4 bytes\n");
		return -EINVAL;
	}

	if (!buf) {
		pr_err("mqnic_char_device: Caught NULL pointer\n");
		return -EINVAL;
	}

	char_dev = (struct mq_char_dev *)file->private_data;

	while (buf_offset < count) {
		copy_err = copy_from_user(&desc_data, &buf[buf_offset],
		                          sizeof(u32));
		if (!copy_err)
		{

			iowrite32(desc_data, char_dev->bar + buf_offset);
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
	size_t buf_offset = 0;
	int rc = 0;
	int copy_err;

	pr_notice("mqnic_char_device: char_read");

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

	while (buf_offset < count)
	{
		desc_data = ioread32(char_dev->bar + buf_offset);
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
		.unlocked_ioctl = char_ctrl_ioctl,
};

struct mq_char_dev *create_mq_char_device(struct mqnic_dev *mq_dev)
{
	dev_t cdevno;
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

	rv = kobject_set_name(&char_dev->cdev.kobj, "mq_registers");

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

	cdevno = MKDEV(char_dev->major, 0);

	/* bring character device live */
	rv = cdev_add(&char_dev->cdev, cdevno, 1);
	if (rv < 0) {
		pr_err("create_mq_char_device: cdev_add failed %d\n", rv);
		goto unregister_region;
	}

	pr_notice("mqnic_char_device: create_mq_char_device succeeded");

	return char_dev;

//del_cdev:
//	cdev_del(&char_dev->cdev);
unregister_region:
	unregister_chrdev_region(cdevno, 1);
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
	cdev_del(&char_dev->cdev);

	unregister_chrdev_region(MKDEV(char_dev->major, 0), 1);
}

void mq_free_char_dev(struct mq_char_dev *char_dev)
{
	pr_notice("mqnic_char_device mq_free_char_dev");
	destroy_mq_char_device(char_dev);
	kfree(char_dev);
}
