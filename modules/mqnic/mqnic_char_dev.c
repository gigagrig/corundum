#include "mqnic.h"

static struct class *g_mqnic_class;
#define MQ_NODE_NAME	"mqnic_char"
#define MQ_CHAR_DEV_COUNT 16


int OpenChar(struct inode *inode, struct file *file)
{
	struct MqnicCharDevice *char_dev;

	pr_info("MqnicCharDevice: char_open\n");

	/* pointer to containing structure of the character device inode */
	char_dev = container_of(inode->i_cdev, struct MqnicCharDevice, cdev);
	if (!char_dev) {
		pr_err("char_dev NULL\n");
		return -EINVAL;
	}

	pr_info("MqnicCharDevice: bar: 0x%llx size: 0x%llx", (uint64_t)char_dev->bar, char_dev->bar_size);
	pr_info("MqnicCharDevice: buf: 0x%llx size: 0x%x", (uint64_t)char_dev->dev_buf, char_dev->dev_buf_size);

	/* create a reference to our char device in the opened file */
	file->private_data = char_dev;

	return 0;
}


/*
 * Called when the device goes from used to unused.
 */
int CloseChar(struct inode *inode, struct file *file)
{
	pr_info("CloseChar: char_close\n");

	return 0;
}

static ssize_t CharWrite(struct file *file, const char __user *buf, size_t count, loff_t *pos)
{
	struct MqnicCharDevice *char_dev;
	u32 desc_data;
	size_t buf_offset;
	int rc;
	int copy_err;
	u8 __iomem *base_addr;

	pr_info("MqnicCharDevice: char_write %lli:%li", *pos, count);

	if (count & 3) {
		pr_err("MqnicCharDevice: Buffer size must be a multiple of 4 bytes\n");
		return -EINVAL;
	}

	if (!buf) {
		pr_err("MqnicCharDevice: Caught NULL pointer\n");
		return -EINVAL;
	}

	if (*pos & 3) {
		pr_err("MqnicCharDevice: address must be a multiple of 4 bytes\n");
		return -EINVAL;
	}

	char_dev = (struct MqnicCharDevice *)file->private_data;

	if (*pos + sizeof(u32) * count > char_dev->bar_size)
	{
		pr_err("MqnicCharDevice: char_read requested memory out of bar\n");
		return -EFAULT;
	}

	buf_offset = 0;
	base_addr = char_dev->bar + *pos;
	while (buf_offset < count) {
		copy_err = copy_from_user(&desc_data, &buf[buf_offset], sizeof(u32));
		if (!copy_err)
		{
			pr_info("char_write 0x%x to 0x%llx", desc_data, *pos);
			MqnicWriteRegister(desc_data, base_addr + buf_offset);
			buf_offset += sizeof(u32);
			rc = buf_offset;
		}
		else
		{
			pr_err("MqnicCharDevice: Error reading data from userspace buffer\n");
			rc = -EINVAL;
			break;
		}
	}

	return rc;
}

static ssize_t CharReadBar(struct file *file, char __user *buf,
                           size_t count, loff_t *pos)
{
	struct MqnicCharDevice *char_dev;
	u32 desc_data;
	size_t buf_offset;
	int rc;
	int copy_err;
	u8 __iomem *base_addr;

	pr_info("MqnicCharDevice: char_read %lli:%li", *pos, count);

	if (count & 3)
	{
		pr_err("MqnicCharDevice: Buffer size must be a multiple of 4 bytes\n");
		return -EINVAL;
	}

	if (!buf)
	{
		pr_err("MqnicCharDevice: Caught NULL pointer\n");
		return -EINVAL;
	}

	if (*pos & 3) {
		pr_err("MqnicCharDevice: address must be a multiple of 4 bytes\n");
		return -EINVAL;
	}

	char_dev = (struct MqnicCharDevice *)file->private_data;

	if (*pos + sizeof(u32) * count > char_dev->bar_size)
	{
		pr_err("MqnicCharDevice: char_read requested memory out of bar\n");
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
			pr_err("MqnicCharDevice: Error writing data to userspace buffer\n");
			rc = -EINVAL;
			break;
		}

		if (rc < 0)
			break;
	}
	return rc;
}

static ssize_t CharReadDevBuf(struct file *file, char __user *buf,
                              size_t count, loff_t *pos)
{
	struct MqnicCharDevice *char_dev;
	int rc;
	int copy_err;
	char *base_addr;
	char *dev_buf_end;

	pr_info("CharReadDevBuf: %lli:%li\n", *pos, count);

	if (!buf)
	{
		pr_err("CharReadDevBuf: Caught NULL pointer\n");
		return -EINVAL;
	}

	char_dev = (struct MqnicCharDevice *)file->private_data;
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
			pr_err("CharReadDevBuf: Error writing data to userspace buffer\n");
			rc = -EINVAL;
		}
	}
	return rc;
}

vm_fault_t VmMmapFault(struct vm_fault *vmf)
{
	struct page *page;
	struct MqnicCharDevice *char_dev;

	char_dev = (struct MqnicCharDevice *)vmf->vma->vm_private_data;
	if (!char_dev) {
		pr_err("VmMmapFault: no device\n");
		return -ENODEV;
	}
	pr_info("VmMmapFault\n");
	page = vmalloc_to_page(char_dev->dev_buf + (vmf->pgoff << PAGE_SHIFT));
	get_page(page);
	vmf->page = page;

	return 0;
}

void VmMmapClose(struct vm_area_struct * area)
{
	pr_info("VmMmapClose\n");
}
void VmMmapOpen(struct vm_area_struct * area)
{
	pr_info("VmMmapOpen\n");
}


static struct vm_operations_struct vm_ops =
{
	.close = VmMmapClose,
	.fault = VmMmapFault,
	.open = VmMmapOpen,
};


int LogCharMmap(struct file *file, struct vm_area_struct *vma)
{
	struct MqnicCharDevice *char_dev;

	pr_info("mqnic_char_dev: char_dev_mmap\n");

	char_dev = (struct MqnicCharDevice *)file->private_data;
	vma->vm_flags |=  VM_DONTEXPAND | VM_DONTDUMP;
	vma->vm_private_data = char_dev;
	vma->vm_ops = &vm_ops;
	VmMmapOpen(vma);
	return 0;
}


static const struct file_operations ctrl_fops = {
		.owner = THIS_MODULE,
		.open = OpenChar,
		.release = CloseChar,
		.read = CharReadBar,
		.write = CharWrite,
};

static const struct file_operations ctrl_log_fops = {
		.owner = THIS_MODULE,
		.open = OpenChar,
		.release = CloseChar,
		.read = CharReadDevBuf,
		.mmap = LogCharMmap
};


int DmaCharMmap(struct file *file, struct vm_area_struct *vma)
{
	struct MqnicCharDevice *char_dev;
	int ret;
	pr_info("DmaCharMmap\n");
	char_dev = (struct MqnicCharDevice *)file->private_data;
	vma->vm_private_data = char_dev;
	ret = dma_mmap_coherent(char_dev->mqniq->dev, vma, char_dev->dev_buf, char_dev->dma_handle, vma->vm_end - vma->vm_start);
	return 0;
}

static long CharIoctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct MqnicCharDevice *dev = (struct MqnicCharDevice*)file->private_data;
	return copy_to_user((void __user *)arg, &(dev->dev_buf_size), sizeof(dev->dev_buf_size)) ? -EFAULT : 0;
}

static const struct file_operations ctrl_dma_fops = {
		.owner = THIS_MODULE,
		.open = OpenChar,
		.release = CloseChar,
		.read = CharReadDevBuf,
		.mmap = DmaCharMmap,
		.compat_ioctl = CharIoctl
};

// 64 bytes header
#define DMA_BUF_HEADER_SIZE 4096 //descriptors queue must be aligned on page size
#define DMA_BUF_NAME_SIZE 24
struct DmaBufferHeader
{
	u32 header_size;
	u32 buffer_size;
	u64 dma_buf_handle;
	char name[DMA_BUF_NAME_SIZE];
};

#define MQNIC_DMA_BUF_SIZE 4*1024*1024

struct MqnicCharDevice *CreateCharDMADevice(struct mqnic_dev *mqnic, const char* name, int num)
{
	struct MqnicCharDevice *char_dev;
	int rv;
	dev_t dev;
	u8 *dma_buf;
	struct DmaBufferHeader *dma_buf_header;

	pr_info("CreateCharDMADevice %s", name);
	char_dev = kmalloc(sizeof(*char_dev), GFP_KERNEL);

	if (!char_dev)
		return NULL;
	memset(char_dev, 0, sizeof(*char_dev));

	char_dev->mqniq = mqnic;
	char_dev->cdev.owner = THIS_MODULE;
	char_dev->bar = 0;
	char_dev->bar_size = 0;

	char_dev->dev_buf = 0;
	char_dev->dev_buf_size = MQNIC_DMA_BUF_SIZE;
	char_dev->dev_buf = dmam_alloc_coherent(mqnic->dev, MQNIC_DMA_BUF_SIZE, &char_dev->dma_handle, GFP_KERNEL);
	if (!char_dev->dev_buf)
	{
		pr_err("CreateCharDMADevice: dma_alloc_coherent failed.\n");
		goto free_cdev;
	}
	dma_buf = char_dev->dev_buf;
	dma_buf_header = (struct DmaBufferHeader *)dma_buf;
	dma_buf_header->header_size = DMA_BUF_HEADER_SIZE;
	dma_buf_header->dma_buf_handle = char_dev->dma_handle;
	dma_buf_header->buffer_size = char_dev->dev_buf_size;
	strncpy(dma_buf_header->name, name, DMA_BUF_NAME_SIZE);

	rv = kobject_set_name(&char_dev->cdev.kobj, name);

	if (rv)
	{
		pr_err("CreateCharDMADevice: kobject_set_name faied.\n");
		goto free_cdev;
	}

	if (num == 0)
	{
		rv = alloc_chrdev_region(&dev, 0, MQ_CHAR_DEV_COUNT, MQ_NODE_NAME);
		if (rv)
		{
			pr_err("CreateCharDMADevice: unable to allocate cdev region %d.\n", rv);
			goto free_cdev;
		}
	}

	cdev_init(&char_dev->cdev, &ctrl_dma_fops);

	char_dev->major = MAJOR(dev);

	char_dev->cdevno = MKDEV(char_dev->major, MINOR(dev) + num);

	/* bring character device live */
	rv = cdev_add(&char_dev->cdev, char_dev->cdevno, 1);
	if (rv < 0) {
		pr_err("CreateCharDMADevice: cdev_add %s failed %d\n", name, rv);
		goto unregister_region;
	}

	char_dev->sys_device = device_create(g_mqnic_class, NULL, char_dev->cdevno, NULL, name);

	if (!char_dev->sys_device) {
		pr_err("CreateCharDMADevice: device_create(%s) failed\n", name);
		goto unregister_region;
	}


	pr_info("CreateCharDMADevice %s succeeded", name);

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
struct MqnicCharDevice *CreateCharLoggerDevice(const char* name, int num)
{
	struct MqnicCharDevice *char_dev;
	int rv;
	dev_t dev;

	pr_info("CreateCharLoggerDevice: %s", name);
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
		pr_err("CreateCharLoggerDevice: kobject_set_name faied.\n");
		goto free_cdev;
	}

	if (num == 0)
	{
		rv = alloc_chrdev_region(&dev, 0, MQ_CHAR_DEV_COUNT, MQ_NODE_NAME);
		if (rv)
		{
			pr_err("CreateCharBar0Device: unable to allocate cdev region %d.\n", rv);
			goto free_cdev;
		}
	}

	cdev_init(&char_dev->cdev, &ctrl_log_fops);

	char_dev->major = MAJOR(dev);

	char_dev->cdevno = MKDEV(char_dev->major, MINOR(dev) + num);

	/* bring character device live */
	rv = cdev_add(&char_dev->cdev, char_dev->cdevno, 1);
	if (rv < 0) {
		pr_err("CreateCharBar0Device: cdev_add %s failed %d\n", name, rv);
		goto unregister_region;
	}

	char_dev->sys_device = device_create(g_mqnic_class, NULL, char_dev->cdevno, NULL, name);

	if (!char_dev->sys_device) {
		pr_err("CreateCharLoggerDevice: device_create(%s) failed\n", name);
		goto unregister_region;
	}


	pr_info("CreateCharLoggerDevice %s succeeded", name);

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

struct MqnicCharDevice *CreateCharBar0Device(const char* name, int num,
                                             u8 __iomem *hw_addr, resource_size_t hw_regs_size)
{
	struct MqnicCharDevice *char_dev;
	int rv;
	dev_t dev;

	pr_info("MqnicCharDevice: CreateCharBar0Device %s", name);
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
		pr_err("CreateCharBar0Device: kobject_set_name faied.\n");
		goto free_cdev;
	}

	if (num == 0)
	{
		rv = alloc_chrdev_region(&dev, 0, MQ_CHAR_DEV_COUNT, MQ_NODE_NAME);
		if (rv)
		{
			pr_err("CreateCharBar0Device: unable to allocate cdev region %d.\n", rv);
			goto free_cdev;
		}
	}

	cdev_init(&char_dev->cdev, &ctrl_fops);

	char_dev->major = MAJOR(dev);

	char_dev->cdevno = MKDEV(char_dev->major, MINOR(dev) + num);

	/* bring character device live */
	rv = cdev_add(&char_dev->cdev, char_dev->cdevno, 1);
	if (rv < 0) {
		pr_err("CreateCharBar0Device: cdev_add %s failed %d\n", name, rv);
		goto unregister_region;
	}

	char_dev->sys_device = device_create(g_mqnic_class, NULL, char_dev->cdevno, NULL, name);

	if (!char_dev->sys_device) {
		pr_err("CreateCharBar0Device: device_create(%s) failed\n", name);
		goto unregister_region;
	}

	pr_info("MqnicCharDevice: CreateCharBar0Device %s succeeded", name);

	return char_dev;


unregister_region:
	unregister_chrdev_region(char_dev->cdevno, MQ_CHAR_DEV_COUNT);
free_cdev:
	kfree(char_dev);
	return NULL;
}


void DestroyCharDevice(struct MqnicCharDevice *char_dev)
{
	pr_info("MqnicCharDevice: DestroyCharDevice");
	if (!char_dev)
	{
		pr_err("DestroyCharDevice: char_dev is empty");
		return;
	}

	if (char_dev->sys_device)
		device_destroy(g_mqnic_class, char_dev->cdevno);
	cdev_del(&char_dev->cdev);

	unregister_chrdev_region(MKDEV(char_dev->major, 0), MQ_CHAR_DEV_COUNT);
}

void FreeBarCharDevice(struct MqnicCharDevice *char_dev)
{
	if (!char_dev)
		return;
	pr_info("MqnicCharDevice %u\n", char_dev->cdevno);
	DestroyCharDevice(char_dev);
	kfree(char_dev);
}

void FreeDmaCharDevice(struct MqnicCharDevice *char_dev)
{
	if (!char_dev)
		return;
	pr_info("FreeDmaCharDevice %u\n", char_dev->cdevno);
	//dma_free_coherent(char_dev->mqniq->dev, char_dev->dev_buf_size, char_dev->dev_buf, char_dev->dma_handle);
	char_dev->dev_buf = 0;
	DestroyCharDevice(char_dev);
	kfree(char_dev);
}

void FreeLogCharDevice(struct MqnicCharDevice *char_dev)
{
	if (!char_dev)
		return;
	pr_info("FreeLogCharDevice %u\n", char_dev->cdevno);
	if (char_dev->dev_buf)
	{
		vfree(char_dev->dev_buf);
		char_dev->dev_buf = 0;
	}
	DestroyCharDevice(char_dev);
	kfree(char_dev);
}


int CharDevicesInit(void)
{
	g_mqnic_class = class_create(THIS_MODULE, MQ_NODE_NAME);
	if (IS_ERR(g_mqnic_class)) {
		pr_err("CharDevicesInit: failed to create class %s", MQ_NODE_NAME);
		return -EINVAL;
	}

	pr_info("MqnicCharDevice: CharDevicesInit finished");

	return 0;
}

void CharDevicesCleanup(void)
{
	if (g_mqnic_class)
		class_destroy(g_mqnic_class);

	pr_info("MqnicCharDevice: mqnic_cdev_cleanup finished");
}
