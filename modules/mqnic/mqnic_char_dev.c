#include "mqnic.h"

static struct class *g_mqnic_class;
#define MQ_NODE_NAME	"mqnic_char"
#define MQ_CHAR_DEV_COUNT 16


int char_open(struct inode *inode, struct file *file)
{
	struct mq_char_dev *char_dev;

	pr_info("mqnic_char_device: char_open\n");

	/* pointer to containing structure of the character device inode */
	char_dev = container_of(inode->i_cdev, struct mq_char_dev, cdev);
	if (!char_dev) {
		pr_err("char_dev NULL\n");
		return -EINVAL;
	}

	pr_info("mqnic_char_device: bar: 0x%llx size: 0x%llx", (uint64_t)char_dev->bar, char_dev->bar_size);
	pr_info("mqnic_char_device: buf: 0x%llx size: 0x%lx", (uint64_t)char_dev->dev_buf, char_dev->dev_buf_size);

	/* create a reference to our char device in the opened file */
	file->private_data = char_dev;

	return 0;
}


/*
 * Called when the device goes from used to unused.
 */
int char_close(struct inode *inode, struct file *file)
{
	pr_info("mqnic_char_device: char_close\n");

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

	pr_info("mqnic_char_device: char_write %lli:%li", *pos, count);

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
			pr_info("char_write 0x%x to 0x%llx", desc_data, *pos);
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

	pr_info("mqnic_char_device: char_read %lli:%li", *pos, count);

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

static ssize_t char_read_dev_buf(struct file *file, char __user *buf,
                                 size_t count, loff_t *pos)
{
	struct mq_char_dev *char_dev;
	int rc;
	int copy_err;
	char *base_addr;
	char *dev_buf_end;

	pr_info("char_read_dev_buf: %lli:%li\n", *pos, count);

	if (!buf)
	{
		pr_err("char_read_dev_buf: Caught NULL pointer\n");
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
			pr_err("char_read_dev_buf: Error writing data to userspace buffer\n");
			rc = -EINVAL;
		}
	}
	return rc;
}

vm_fault_t vm_mmap_fault(struct vm_fault *vmf)
{
	struct page *page;
	struct mq_char_dev *char_dev;

	char_dev = (struct mq_char_dev *)vmf->vma->vm_private_data;
	if (!char_dev) {
		pr_err("vm_mmap_fault: no device\n");
		return -ENODEV;
	}
	pr_info("vm_mmap_fault\n");
	page = vmalloc_to_page(char_dev->dev_buf + (vmf->pgoff << PAGE_SHIFT));
	get_page(page);
	vmf->page = page;

	return 0;
}

void vm_mmap_close(struct vm_area_struct * area)
{
	pr_info("vm_mmap_close\n");
}
void vm_mmap_open(struct vm_area_struct * area)
{
	pr_info("vm_mmap_open\n");
}


static struct vm_operations_struct vm_ops =
{
	.close = vm_mmap_close,
	.fault = vm_mmap_fault,
	.open = vm_mmap_open,
};


int char_dev_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct mq_char_dev *char_dev;

	pr_info("mqnic_char_dev: char_dev_mmap\n");

	char_dev = (struct mq_char_dev *)file->private_data;
	vma->vm_flags |=  VM_DONTEXPAND | VM_DONTDUMP;
	vma->vm_private_data = char_dev;
	vma->vm_ops = &vm_ops;
	vm_mmap_open(vma);
	return 0;
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
		.read = char_read_dev_buf,
		.mmap = char_dev_mmap
};


int dma_char_dev_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct mq_char_dev *char_dev;
	int ret;
	pr_info("dma_char_dev_mmap\n");
	char_dev = (struct mq_char_dev *)file->private_data;
	vma->vm_private_data = char_dev;
	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
	ret = dma_mmap_coherent(char_dev->mqniq->dev, vma, char_dev->dev_buf, char_dev->dma_handle, vma->vm_end - vma->vm_start);
	return 0;
}

static const struct file_operations ctrl_dma_fops = {
		.owner = THIS_MODULE,
		.open = char_open,
		.release = char_close,
		.read = char_read_dev_buf,
		.mmap = dma_char_dev_mmap
};

// 64 bytes header
struct DmaBufferHeader
{
	u32 header_size;
	u32 buffer_size;
	u64 dma_buf_handle;
	char name[24];
};



#define MQNIC_TX_BUF_SIZE 1024*1024
struct mq_char_dev *create_mq_char_dma(struct mqnic_dev *mqnic, const char* name, int num)
{
	struct mq_char_dev *char_dev;
	int rv;
	dev_t dev;
	u8 *dma_buf;
	struct DmaBufferHeader *dma_buf_header;

	pr_info("create_mq_char_dma %s", name);
	char_dev = kmalloc(sizeof(*char_dev), GFP_KERNEL);

	if (!char_dev)
		return NULL;
	memset(char_dev, 0, sizeof(*char_dev));

	char_dev->mqniq = mqnic;
	char_dev->cdev.owner = THIS_MODULE;
	char_dev->bar = 0;
	char_dev->bar_size = 0;

	char_dev->dev_buf = 0;
	char_dev->dev_buf_size = MQNIC_TX_BUF_SIZE;
	char_dev->dev_buf = dmam_alloc_coherent(mqnic->dev, MQNIC_TX_BUF_SIZE, &char_dev->dma_handle, GFP_KERNEL);
	if (!char_dev->dev_buf)
	{
		pr_err("create_mq_char_dma: dma_alloc_coherent failed.\n");
		goto free_cdev;
	}
	dma_buf = char_dev->dev_buf;
	dma_buf_header = (struct DmaBufferHeader *)dma_buf;
	dma_buf_header->header_size = 4096;
	dma_buf_header->dma_buf_handle = char_dev->dma_handle;
	dma_buf_header->buffer_size = char_dev->dev_buf_size;
	strncpy(dma_buf_header->name, name, 24);

	rv = kobject_set_name(&char_dev->cdev.kobj, name);

	if (rv)
	{
		pr_err("create_mq_char_dma: kobject_set_name faied.\n");
		goto free_cdev;
	}

	if (num == 0)
	{
		rv = alloc_chrdev_region(&dev, 0, MQ_CHAR_DEV_COUNT, MQ_NODE_NAME);
		if (rv)
		{
			pr_err("create_mq_char_dma: unable to allocate cdev region %d.\n", rv);
			goto free_cdev;
		}
	}

	cdev_init(&char_dev->cdev, &ctrl_dma_fops);

	char_dev->major = MAJOR(dev);

	char_dev->cdevno = MKDEV(char_dev->major, MINOR(dev) + num);

	/* bring character device live */
	rv = cdev_add(&char_dev->cdev, char_dev->cdevno, 1);
	if (rv < 0) {
		pr_err("create_mq_char_dma: cdev_add %s failed %d\n", name, rv);
		goto unregister_region;
	}

	char_dev->sys_device = device_create(g_mqnic_class, NULL, char_dev->cdevno, NULL, name);

	if (!char_dev->sys_device) {
		pr_err("create_mq_char_dma: device_create(%s) failed\n", name);
		goto unregister_region;
	}


	pr_info("create_mq_char_dma %s succeeded", name);

	return char_dev;

	unregister_region:
	unregister_chrdev_region(char_dev->cdevno, MQ_CHAR_DEV_COUNT);

free_cdev:
	if (char_dev->dev_buf)
	{
		//dma_free_coherent(char_dev->mqniq->dev, char_dev->dev_buf_size, char_dev->dev_buf, char_dev->dma_handle);
		char_dev->dev_buf = 0;
	}
	kfree(char_dev);
	return NULL;
}

#define MQNIC_LOG_BUF_SIZE 16*1024*1024
struct mq_char_dev *create_mq_char_log_device(const char* name, int num)
{
	struct mq_char_dev *char_dev;
	int rv;
	dev_t dev;

	pr_info("create_mq_char_log_device: create_mq_char_device %s", name);
	char_dev = kmalloc(sizeof(*char_dev), GFP_KERNEL);

	if (!char_dev)
		return NULL;
	memset(char_dev, 0, sizeof(*char_dev));

	char_dev->cdev.owner = THIS_MODULE;
	char_dev->bar = 0;
	char_dev->bar_size = 0;

	char_dev->dev_buf = vmalloc_user(MQNIC_LOG_BUF_SIZE);
	if (!char_dev->dev_buf)
		goto free_cdev;
	char_dev->dev_buf_size = MQNIC_LOG_BUF_SIZE;

	rv = kobject_set_name(&char_dev->cdev.kobj, name);

	if (rv)
	{
		pr_err("create_mq_char_log_device: kobject_set_name faied.\n");
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


	pr_info("create_mq_char_log_device %s succeeded", name);

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

	pr_info("mqnic_char_device: create_mq_char_device %s", name);
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


	pr_info("mqnic_char_device: create_mq_char_device %s succeeded", name);

	return char_dev;


unregister_region:
	unregister_chrdev_region(char_dev->cdevno, MQ_CHAR_DEV_COUNT);
free_cdev:
	kfree(char_dev);
	return NULL;
}


void destroy_mq_char_device(struct mq_char_dev *char_dev)
{
	pr_info("mqnic_char_device: destroy_mq_char_device");
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
	if (!char_dev)
		return;
	pr_info("mqnic_char_device %u\n", char_dev->cdevno);
	destroy_mq_char_device(char_dev);
	kfree(char_dev);
}

void mq_free_dma_char_dev(struct mq_char_dev *char_dev)
{
	if (!char_dev)
		return;
	pr_info("mq_free_dma_char_dev %u\n", char_dev->cdevno);
	//dma_free_coherent(char_dev->mqniq->dev, char_dev->dev_buf_size, char_dev->dev_buf, char_dev->dma_handle);
	char_dev->dev_buf = 0;
	destroy_mq_char_device(char_dev);
	kfree(char_dev);
}

void mq_free_log_char_dev(struct mq_char_dev *char_dev)
{
	if (!char_dev)
		return;
	pr_info("mq_free_log_char_dev %u\n", char_dev->cdevno);
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

	pr_info("mqnic_char_device: mq_cdev_init finished");

	return 0;
}

void mqnic_cdev_cleanup(void)
{
/*	if (cdev_cache)
		kmem_cache_destroy(cdev_cache);*/

	if (g_mqnic_class)
		class_destroy(g_mqnic_class);

	pr_info("mqnic_char_device: mqnic_cdev_cleanup finished");
}
