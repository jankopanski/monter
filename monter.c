#include <linux/module.h>
#include <linux/device.h>
#include <linux/pci.h>
#include <linux/circ_buf.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/idr.h>
#include <linux/interrupt.h>
#include <linux/dma-mapping.h>
#include <linux/dmapool.h>
#include <linux/spinlock.h>
#include <asm/uaccess.h>
#include <linux/errno.h>
#include <linux/major.h>
#include <linux/kernel.h>
// #include <asm/memory.h>
// #include <linux/mm.h>
// #include <asm/atomic.h>
#include "monter.h"
#include "monter_ioctl.h"

MODULE_AUTHOR("Jan Kopański");
MODULE_LICENSE("GPL");

// static

// int monter_minor = 0;
// unsigned int monter_num_devices = 2; // 256
// const char *monter_name = "monter";

#define MONTER_MAX_COUNT 256

static struct class *monter_class = NULL;
dev_t dev_base = 0; // zakodowany major + minor
int monter_major = 0;
static DEFINE_IDR(monter_idr);

struct monter_dev {
  // być może będzie trzeba dodać current_context dla funkcji obsługi przerwań
  // struct device *dev; // class, pole dev wewnątrz pdev
  struct pci_dev *pdev;
  struct cdev cdev;
	void __iomem *bar0;
  struct monter_context *current_context;
};

struct monter_dev *monter_devices;

struct monter_context {
  struct monter_dev *mdev;
  void *data_area;
  dma_addr_t dma_handle;
  size_t data_size;
  int state;
};

static irqreturn_t monter_irq_handler(int irq, void *dev) {
  struct monter_dev *monter_dev = dev;
  uint32_t intr;

  intr = ioread32(monter_dev->bar0 + MONTER_INTR);
  printk(KERN_INFO "interrupt request %u", intr);
  // printk(KERN_WARNING "interrupt request %ud", intr);
  if (!intr) {
    return IRQ_NONE;
  }
  iowrite32(intr, monter_dev->bar0 + MONTER_INTR);

  return IRQ_HANDLED;
}

static void switch_context(struct monter_context *context) {
  uint32_t i, value;
  printk(KERN_INFO "context_switch");
  printk(KERN_INFO "dma_handle context_switch: %llu", context->dma_handle);
  for (i = 0; i < 16; ++i) {
    value = MONTER_CMD_PAGE(i, MONTER_CMD_PAGE_ADDR(context->dma_handle + i * 4096), 0);
    printk(KERN_INFO "value: %u %u", i, value);
    iowrite32(value, context->mdev->bar0 + MONTER_FIFO_SEND);
  }
  context->mdev->current_context = context;
}

static long monter_ioctl(struct file*, unsigned int, unsigned long); // TODO remove
static int monter_mmap(struct file *, struct vm_area_struct *);

static ssize_t monter_read(struct file *filp, char __user *buf, size_t count, loff_t *f_pos) {
  struct monter_context *context = filp->private_data;
  // uint32_t *dane = (uint32_t*)1018036224;//(uint32_t*)context->dma_handle;
  uint32_t *dane = NULL;
  uint32_t addr, run, status1, status2;
	printk(KERN_INFO "monter_read");
  monter_ioctl(filp, MONTER_IOCTL_SET_SIZE, 65536);
  dane = context->data_area;
  // monter_mmap()
  printk(KERN_INFO "AAA");
  switch_context(filp->private_data);
  printk(KERN_INFO "BBB: %p %p %llu", dane, context->data_area, context->dma_handle);
  // zlecenie operacji mnożenia
  *dane = 1;
  *(dane + 1) = 2;
  printk(KERN_INFO "CCC");
  // addr = MONTER_CMD_ADDR_AB(dane, dane + 1, 0);
  // run = MONTER_CMD_RUN_MULT(0, dane + 2, 0);
  status1 = ioread32(context->mdev->bar0 + MONTER_STATUS);
  printk(KERN_INFO "MULT STATUS1: %u", status1);
  addr = MONTER_CMD_ADDR_AB(context->dma_handle, context->dma_handle + 4, 0);
  run = MONTER_CMD_RUN_MULT(0, context->dma_handle + 8, 0);
  iowrite32(addr, context->mdev->bar0 + MONTER_FIFO_SEND);
  iowrite32(run, context->mdev->bar0 + MONTER_FIFO_SEND);
  status2 = ioread32(context->mdev->bar0 + MONTER_STATUS);
  printk(KERN_INFO "MULT STATUS2: %u", status2);
  // wait
  // ioread32();
  printk(KERN_INFO "MULT monter_read: %u, %u", addr, run);
  return 0;
}

static int send_addr_ab(struct monter_context *context, uint32_t data) {
  uint32_t addr_a = MONTER_SWCMD_ADDR_A(data), addr_b = MONTER_SWCMD_ADDR_B(data);
  uint32_t addr_ab = MONTER_CMD_ADDR_AB(addr_a, addr_b, 0);
  // TODO jakaś walidacja? sprawdzenie zakresu
  printk(KERN_INFO "send_addr_ab");
  iowrite32(addr_ab, context->mdev->bar0 + MONTER_FIFO_SEND);
  return 0;
}

static int send_run_op(struct monter_context *context, uint32_t data, int mult_or_redc) {
  uint32_t size_m1 = MONTER_SWCMD_RUN_SIZE(data), addr_d = MONTER_SWCMD_ADDR_D(data);
  uint32_t run_op = 0;
  printk(KERN_INFO "send_run_op: %d", mult_or_redc);
  if (!(data & 0x1000)) {
    printk(KERN_WARNING "send_run_op bit 17");
    return -EINVAL;
  }
  if (mult_or_redc == 0) run_op = MONTER_SWCMD_RUN_MULT(size_m1, addr_d);
  else if (mult_or_redc == 1) run_op = MONTER_SWCMD_RUN_REDC(size_m1, addr_d);
  else {
    printk(KERN_WARNING "send_run_op");
    return -EINVAL;
  }
  iowrite32(run_op, context->mdev->bar0 + MONTER_FIFO_SEND);
  return 0;
}

static ssize_t monter_write(struct file *filp, const char __user *buf, size_t count, loff_t *f_pos) {
  // TODO sprawdzić uprawnienia
  // TODO czy nie poprawić - rozbić wczytywania na części, bufor na polecenia
  struct monter_context *context = filp->private_data;
  // long pos = filp->f_pos;
  int ret;
  unsigned long read;
  uint32_t cmd, data;
	printk(KERN_INFO "monter_write");
  if (context->state != 1) {
    printk(KERN_WARNING "monter_write state: %d", context->state);
    return -EINVAL;
  }
  if (!(count % 4)) {
    printk(KERN_WARNING "monter_write count: %lu", count);
    return -EINVAL;
  }
  if (filp->f_pos == count) return 0;
  read = copy_from_user(&data, buf, 4);
  if (read) {
    printk(KERN_WARNING "copy_from_user: %lu", read);
    return -EINVAL;
  }
  *f_pos = filp->f_pos + 4;
  if (context->mdev->current_context != context) {
    switch_context(context);
  }
  cmd = MONTER_SWCMD_TYPE(data);
  switch (cmd) {
    case MONTER_SWCMD_TYPE_ADDR_AB:
      ret = send_addr_ab(context, data);
      if (ret) return ret;
      break;
    case MONTER_SWCMD_TYPE_RUN_MULT:
      ret = send_run_op(context, data, 0); // TODO dodać makra? na MULT I REDC
      if (ret) return ret;
      break;
    case MONTER_SWCMD_TYPE_RUN_REDC:
      ret = send_run_op(context, data, 1);
      if (ret) return ret;
      break;
    default:
      return -EINVAL;
  }
  return 4;
}

static long monter_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
  size_t size = (size_t) arg;
  struct monter_context *context = filp->private_data;
  printk(KERN_INFO "monter_ioctl");
  // void *data_area;
  switch (cmd) {
    case MONTER_IOCTL_SET_SIZE:
      if (context->state) {
        printk(KERN_WARNING "context->state: %u", context->state);
        return -EINVAL;
      }
      if (size <= 0 && size > 65536 && size % 4096 != 0) {
        printk(KERN_WARNING "ioctl size: %lu", size);
        return -EINVAL;
      }
      context->data_area = dma_alloc_coherent(&context->mdev->pdev->dev, size, &context->dma_handle, GFP_KERNEL); // GFP_DMA32
      if (IS_ERR_OR_NULL(context->data_area)) {
        printk(KERN_WARNING "dma_alloc_coherent: %p, %llu", context->data_area, context->dma_handle);
        return PTR_ERR(context->data_area);
      }
      printk(KERN_INFO "dma_handle ioctl: %llu, %p", context->dma_handle, context->data_area);
      context->data_size = size;
      context->state = 1;
      return 0;
    default:
      return -ENOTTY;
  }
}

static const struct vm_operations_struct monter_vm_ops = { };

static int monter_mmap(struct file *flip, struct vm_area_struct *vm_area) {
  long ret;
  struct monter_context *context = flip->private_data;
  unsigned long size = vm_area->vm_end - vm_area->vm_start;
  // unsigned long pfn = virt_to_pfn(context->data_area);
  unsigned long pfn = virt_to_phys(context->data_area) >> PAGE_SHIFT;
  if (context->state != 1) {
    printk(KERN_WARNING "monter_mmap state: %d", context->state);
  }
  vm_area->vm_ops = &monter_vm_ops; // ???
  printk(KERN_INFO "mmap");
  if (vm_area->vm_flags != (VM_READ | VM_WRITE | VM_SHARED)) {
    printk(KERN_WARNING "vm_flags");
    return -EINVAL;
  }
  ret = remap_pfn_range(vm_area, vm_area->vm_start, pfn, size, vm_area->vm_page_prot);
  if (IS_ERR_VALUE(ret)) {
    printk(KERN_WARNING "remap_pfn_range");
    return ret;
  }
  return 0;
}

static int monter_open(struct inode *inode, struct file *filp) {
  int major = MAJOR(inode->i_rdev), minor = MINOR(inode->i_rdev);
  struct monter_dev *monter_dev;
  struct monter_context *context;

  printk(KERN_INFO "monter_open");

  monter_dev = container_of(inode->i_cdev, struct monter_dev, cdev);
  context = kmalloc(sizeof(struct monter_context), GFP_KERNEL);
  if (!context) {
    printk(KERN_WARNING "kmalloc %d:%d", major, minor);
    return -ENOMEM;
  }
  context->mdev = monter_dev;
  context->data_area = NULL;
  context->dma_handle = 0;
  context->data_size = 0;
  context->state = 0;
  monter_dev->current_context = NULL; // context
  // u->mode = -1;
  filp->private_data = context;

  return 0;
	// dev_t devno = inode->i_rdev; // adresować urządzenie po minor
	// int major = MAJOR(devno), minor = MINOR(devno);
	// struct cdev cdev = *(inode->i_cdev); // blackbox?
	// int mod = (int)filp->f_mode;
	// printk(KERN_WARNING "OPEN");
	// printk(KERN_INFO "major: %d, minor: %d, mod: %d", major, minor, mod);
  // return 0;
}

static int monter_release(struct inode *inode, struct file *filp) {
  struct monter_context *context = filp->private_data;

	printk(KERN_INFO "monter_release");
	// printk(KERN_WARNING "RELEASE");
  // zwalnianie dma_alloc_coherent
  if (context->state) {
    dma_free_coherent(&context->mdev->pdev->dev, context->data_size,
      context->data_area, context->dma_handle);
  }
  kfree(context);
	return 0;
}

// release - close
struct file_operations monter_fops = {
  .owner = THIS_MODULE,
  .read = monter_read,
  .write = monter_write,
  .unlocked_ioctl = monter_ioctl,
  .mmap = monter_mmap,
  .open = monter_open,
  .release = monter_release,
  //.fsync = monter_fsync,
};

static int monter_probe(struct pci_dev *dev, const struct pci_device_id *id) {
	long ret;
  uint32_t reg = 0;
	struct monter_dev *monter_dev;
	struct device *device;
	int minor;

	printk(KERN_INFO "pci_probe");

	monter_dev = kmalloc(sizeof(struct monter_dev), GFP_KERNEL);
  // printk(KERN_INFO "%p", monter_dev);
	if (!monter_dev) {
		printk(KERN_WARNING "kmalloc");
		return -ENOMEM;
	}
	monter_dev->pdev = dev;
	cdev_init(&monter_dev->cdev, &monter_fops);

	ret = pci_enable_device(dev);
	if (IS_ERR_VALUE(ret)) {
		printk(KERN_WARNING "pci_enable_device");
		goto err_pci_enable;
	}

	ret = pci_request_region(dev, 0, "monter");
	if (IS_ERR_VALUE(ret)) { // ret == EBUSY
		printk(KERN_WARNING "pci_request_region");
		goto err_pci_region;
	}

	monter_dev->bar0 = pci_iomap(dev, 0, 0);
	if (IS_ERR(monter_dev->bar0)) {
		printk(KERN_WARNING "pci_iomap");
		ret = PTR_ERR(monter_dev->bar0);
		goto err_pci_iomap;
	}

  reg = ioread32(monter_dev->bar0 + MONTER_ENABLE);
  printk(KERN_INFO "ENABLE0: %u", reg);
  reg = ioread32(monter_dev->bar0 + MONTER_STATUS);
  printk(KERN_INFO "STATUS0: %u", reg);
  reg = ioread32(monter_dev->bar0 + MONTER_INTR);
  printk(KERN_INFO "INTR0: %u", reg);
  reg = ioread32(monter_dev->bar0 + MONTER_INTR_ENABLE);
  printk(KERN_INFO "INTR_ENABLE0: %u", reg);

  iowrite32(3, monter_dev->bar0 + MONTER_RESET);
  iowrite32(7, monter_dev->bar0 + MONTER_INTR);
  iowrite32(7, monter_dev->bar0 + MONTER_INTR_ENABLE);
  iowrite32(1, monter_dev->bar0 + MONTER_ENABLE); // TODO zmaienić na 5 dla CMD

  reg = ioread32(monter_dev->bar0 + MONTER_ENABLE);
  printk(KERN_INFO "ENABLE1: %u", reg);
  reg = ioread32(monter_dev->bar0 + MONTER_STATUS);
  printk(KERN_INFO "STATUS1: %u", reg);
  reg = ioread32(monter_dev->bar0 + MONTER_INTR);
  printk(KERN_INFO "INTR1: %u", reg);
  reg = ioread32(monter_dev->bar0 + MONTER_INTR_ENABLE);
  printk(KERN_INFO "INTR_ENABLE1: %u", reg);

	pci_set_master(dev);
	ret = dma_set_mask_and_coherent(&dev->dev, DMA_BIT_MASK(32));
  if (IS_ERR_VALUE(ret)) {
    printk(KERN_WARNING "dma_set_mask_and_coherent");
    goto err_dma_mask;
  }

	ret = request_irq(dev->irq, monter_irq_handler, IRQF_SHARED, "monter", monter_dev);
  if (IS_ERR_VALUE(ret)) {
    printk(KERN_WARNING "request_irq");
    goto err_irq;
  }

	// mutex_init

  // reg = ioread32(monter_dev->bar0 + MONTER_ENABLE);
  // printk(KERN_INFO "ENABLE2: %u", reg);
  // reg = ioread32(monter_dev->bar0 + MONTER_STATUS);
  // printk(KERN_INFO "STATUS2: %u", reg);
  // reg = ioread32(monter_dev->bar0 + MONTER_INTR);
  // printk(KERN_INFO "INTR2: %u", reg);
  // reg = ioread32(monter_dev->bar0 + MONTER_INTR_ENABLE);
  // printk(KERN_INFO "INTR_ENABLE2: %u", reg);

	// iowrite32

	minor = idr_alloc(&monter_idr, monter_dev, 0, MONTER_MAX_COUNT, GFP_KERNEL);
	if (IS_ERR_VALUE((long)minor)) {
		printk(KERN_WARNING "idr_alloc");
		ret = minor;
		goto err_idr;
	}

	ret = cdev_add(&monter_dev->cdev, dev_base + minor, 1);
	if (IS_ERR_VALUE(ret)) {
		printk(KERN_WARNING "cdev_add");
		goto err_cdev;
	}

	device = device_create(monter_class, &dev->dev, monter_dev->cdev.dev, monter_dev, "monter%d", minor);
	if (IS_ERR(device)) {
		printk(KERN_WARNING "device_create");
		ret = PTR_ERR(device);
		goto err_dev;
	}

  monter_dev->current_context = NULL;
	pci_set_drvdata(dev, monter_dev);

  reg = ioread32(monter_dev->bar0 + MONTER_ENABLE);
  printk(KERN_INFO "ENABLE2: %u", reg);
  reg = ioread32(monter_dev->bar0 + MONTER_STATUS);
  printk(KERN_INFO "STATUS2: %u", reg);
  reg = ioread32(monter_dev->bar0 + MONTER_INTR);
  printk(KERN_INFO "INTR2: %u", reg);
  reg = ioread32(monter_dev->bar0 + MONTER_INTR_ENABLE);
  printk(KERN_INFO "INTR_ENABLE2: %u", reg);

  printk(KERN_INFO "probe end");
  return 0;

	device_destroy(monter_class, monter_dev->cdev.dev);
err_dev:
	cdev_del(&monter_dev->cdev);
err_cdev:
	idr_remove(&monter_idr, minor);
err_idr:
  free_irq(dev->irq, monter_dev);
err_irq:
err_dma_mask:
	pci_iounmap(dev, monter_dev->bar0);
err_pci_iomap:
	pci_release_region(dev, 0);
err_pci_region:
	pci_disable_device(dev);
err_pci_enable:
	kfree(monter_dev);
	return ret;
}

static void monter_remove(struct pci_dev *dev) {
  struct monter_dev *monter_dev = pci_get_drvdata(dev);
  printk(KERN_INFO "monter_remove");

  // iowrite32(0, aesdev->bar0 + AESDEV_ENABLE);
  // iowrite32(0, aesdev->bar0 + AESDEV_INTR_ENABLE);
  iowrite32(3, monter_dev->bar0 + MONTER_RESET);
  device_destroy(monter_class, monter_dev->cdev.dev);
  cdev_del(&monter_dev->cdev);
  idr_remove(&monter_idr, MINOR(monter_dev->cdev.dev));
  free_irq(dev->irq, monter_dev);
  pci_iounmap(dev, monter_dev->bar0);
  pci_release_region(dev, 0);
  pci_disable_device(dev);
  kfree(monter_dev);
}

// tablica za ID urządzenia pci
static struct pci_device_id monter_id_table[] = {
	{ PCI_DEVICE(MONTER_VENDOR_ID, MONTER_DEVICE_ID), },
	{ 0, }
};
MODULE_DEVICE_TABLE(pci, monter_id_table);

static struct pci_driver monter_driver = {
  .name = "monter",
  .id_table = monter_id_table,
  .probe = monter_probe,
  .remove = monter_remove,
};

// static void monter_setup_cdev(struct monter_dev *dev, int index) {
//   int err;
//
//   dev->devno = MKDEV(monter_major, monter_minor + index);
//   cdev_init(&dev->cdev, &monter_fops);
//   dev->cdev.owner = THIS_MODULE;
//   dev->cdev.ops = &monter_fops;
//   err = cdev_add(&dev->cdev, dev->devno, 1);
//   if (err) {
//     printk(KERN_WARNING "cdev_add");
//     return;
//   }
//
//   dev->dev = device_create(monter_class, 0, dev->devno, 0, "monter%d", index);
//   if (IS_ERR(dev->dev)) {
//     printk(KERN_WARNING "device_create");
//     dev->dev = 0;
//   }
// }

static int __init monter_init(void) {
  long ret = -EINVAL;
	// int i;

	monter_class = class_create(THIS_MODULE, "monter");
  if (IS_ERR(monter_class)) {
    printk(KERN_WARNING "class_create");
    return PTR_ERR(monter_class);
  }

  ret = alloc_chrdev_region(&dev_base, 0, MONTER_MAX_COUNT, "monter");
  if (IS_ERR_VALUE(ret)) {
    printk(KERN_WARNING "alloc_chrdev_region");
		goto err_class;
  }
  monter_major = MAJOR(dev_base);

  ret = pci_register_driver(&monter_driver);
  if (IS_ERR_VALUE(ret)) {
    printk(KERN_WARNING "pci_register_driver");
    goto err_chrdev;
  }
  return 0;

err_chrdev:
	unregister_chrdev_region(dev_base, MONTER_MAX_COUNT);
err_class:
	class_destroy(monter_class);
	return ret;
}

static void __exit monter_exit(void) {
  printk(KERN_INFO "monter_exit");
	pci_unregister_driver(&monter_driver);
	unregister_chrdev_region(dev_base, MONTER_MAX_COUNT);
	class_destroy(monter_class);
}

module_init(monter_init);
module_exit(monter_exit);
