#include "mqnic.h"



static DEFINE_MUTEX(xdev_mutex);


static inline int xdev_list_add(struct mq_char_dev *xdev)
{

	return 0;
}

void xdma_device_close(struct pci_dev *pdev, void *dev_hndl);


void *xdma_device_open(const char *mname, struct pci_dev *pdev)
{
	struct mqnic_dev_dev *xdev = 0;
	int rv = 0;

	return 0;

free_xdev:
	xdma_device_close(pdev, xdev);

}

void xdma_device_close(struct pci_dev *pdev, void *dev_hndl)
{
	struct mq_char_dev *xdev = (struct mq_char_dev *)dev_hndl;

	if (xdev->pdev != pdev) {
		printk(KERN_ERR "pci_dev(0x%lx) != pdev(0x%lx)\n",
		       (unsigned long)xdev->pdev, (unsigned long)pdev);
	}

	kfree(xdev);
}


int char_open(struct inode *inode, struct file *file)
{
	struct mq_char_dev *char_dev;

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
	struct xdma_cdev *xcdev = (struct xdma_cdev *)filp->private_data;
	struct mq_char_dev *xdev;
	//struct xdma_ioc_base ioctl_obj;
	long result = 0;
	int rv;


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


static const struct file_operations ctrl_fops = {
		.owner = THIS_MODULE,
		.open = char_open,
		//.release = char_close,
		//.read = char_ctrl_read,
		//.write = char_ctrl_write,
		//.mmap = bridge_mmap,
		.unlocked_ioctl = char_ctrl_ioctl,
};

#define MAGIC_CHAR	0xCCCCCCCCUL


struct mq_char_dev *create_mq_char_device(struct mqnic_dev *mq_dev)
{
	struct mq_char_dev *mq_cdev = kmalloc(sizeof(*mq_cdev   ), GFP_KERNEL);

	if (!mq_cdev)
		return NULL;
	memset(mq_cdev, 0, sizeof(*mq_cdev));

	mq_cdev->cdev.owner = THIS_MODULE;

	int rv = kobject_set_name(&mq_cdev->cdev.kobj, "mq_reg_device");

	if (rv)
	{
		pr_err("create_mq_char_device: kobject_set_name faied.\n");
		return NULL;
	}

	cdev_init(&mq_cdev->cdev, &ctrl_fops);

	dev_t dev;
	rv = alloc_chrdev_region(&dev, 0, 1, "mq");

	if (rv) {
		pr_err("create_mq_char_device: unable to allocate cdev region %d.\n", rv);
		return rv;
	}

	int major = MAJOR(dev);

	dev_t cdevno = MKDEV(major, 0);

	/* bring character device live */
	rv = cdev_add(&mq_cdev->cdev, cdevno, 1);
	if (rv < 0) {
		pr_err("create_mq_char_device: cdev_add failed %d\n", rv);
		goto unregister_region;
	}

	/* create device on our class */
	//rv = create_sys_device(xcdev, type);

	return 0;

	del_cdev:
	cdev_del(&mq_cdev->cdev);
	unregister_region:
	unregister_chrdev_region(cdevno, 1);
	return rv;

	return mq_cdev;
}



static int destroy_xcdev(struct xdma_cdev *cdev)
{
	if (!cdev) {
		pr_warn("cdev NULL.\n");
		return -EINVAL;
	}


	if (!cdev->xdev) {
		pr_err("xdev NULL\n");
		return -EINVAL;
	}
	

	cdev_del(&cdev->cdev);

	return 0;
}


void destroy_mq_char_device(struct xdma_pci_dev *xpdev)
{
	int i = 0;
	int rv;

	rv = destroy_xcdev(&xpdev->ctrl_cdev);
	if (rv < 0)
	{
		pr_err("destroy_mq_char_device Failed to destroy cdev %d error 0x%x\n", i, rv);
	}


	unregister_chrdev_region(MKDEV(xpdev->major, 0), 1);
}