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
  // dev_t devno;
  struct pci_dev *pdev;
  struct cdev cdev;
	void __iomem *bar0;
  // struct device *dev; // do klasy urządzeń potrzebnych do ich dodania do sysfs
};

struct monter_dev *monter_devices;

ssize_t monter_read(struct file *filp, char __user *buf, size_t count, loff_t *f_pos) {
	printk(KERN_INFO "monter_read");
	printk(KERN_WARNING "READ");
  return 0;
}

ssize_t scull_write(struct file *filp, const char __user *buf, size_t count, loff_t *f_pos) {
	printk(KERN_INFO "scull_write");
	printk(KERN_WARNING "WRITE");
  return 0;
}

long scull_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
	printk(KERN_INFO "scull_ioctl");
  return 0;
}

int mmap(struct file *flip, struct vm_area_struct *vm_area) {
	printk(KERN_INFO "mmap");
	printk(KERN_WARNING "MMAP");
  return 0;
}

int monter_open(struct inode *inode, struct file *filp) {
	dev_t devno = inode->i_rdev; // adresować urządzenie po minor
	int major = MAJOR(devno), minor = MINOR(devno);
	struct cdev cdev = *(inode->i_cdev); // blackbox?
	int mod = (int)filp->f_mode;
	printk(KERN_INFO "monter_open");
	printk(KERN_WARNING "OPEN");
	printk(KERN_INFO "major: %d, minor: %d, mod: %d", major, minor, mod);
  return 0;
}

int scull_release(struct inode *inode, struct file *filp) {
	printk(KERN_INFO "scull_release");
	printk(KERN_WARNING "RELEASE");
	return 0;
}

// release - close
struct file_operations monter_fops = {
  .owner = THIS_MODULE,
  .read = monter_read,
  // write: monter_write,
  // ioctl: monter_ioctl,
  // mmap: monter_mmap,
  .open = monter_open,
  // release: monter_release,
  // fsync: monter_fsync,
};

static int monter_probe(struct pci_dev *dev, const struct pci_device_id *id) {
	long ret;
	struct monter_dev *monter_dev;
	struct device *device;
	int minor;
	// int BAR0 = 0;
	// void __iomem *baraddr;
	// unsigned int reg;

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
	if (IS_ERR(monter_dev->bar0)) { // !baraddr
		printk(KERN_WARNING "pci_iomap");
		ret = PTR_ERR(monter_dev->bar0);
		goto err_pci_iomap;
	}

	// pci_set_master
	// dma_set_mask

	// ret = request_irq(dev->irq, monter_irq, ) // przerwania

	// mutex_init

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

	pci_set_drvdata(dev, monter_dev);
	// reg = ioread32(baraddr);
	// printk(KERN_INFO "ioread32: %ud", reg);
	// iowrite32(0, baraddr);
	// printk(KERN_INFO "iowrite32");
	// reg = ioread32(baraddr);
	// printk(KERN_INFO "ioread32: %ud", reg);
  return 0;

	device_destroy(monter_class, monter_dev->cdev.dev);
err_dev:
	cdev_del(&monter_dev->cdev);
err_cdev:
	idr_remove(&monter_idr, minor);
err_idr:
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
  device_destroy(monter_class, monter_dev->cdev.dev);
  cdev_del(&monter_dev->cdev);
  idr_remove(&monter_idr, MINOR(monter_dev->cdev.dev));
  // free_irq(dev->irq, aesdev);
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

  // monter_devices = kmalloc(monter_num_devices * sizeof(struct monter_dev), GFP_KERNEL);
  // if (!monter_devices) {
  //   ret = - ENOMEM;
  //   // monter_cleanup_module();
  //   return ret;
  // }
  // memset(monter_devices, 0, monter_num_devices * sizeof(struct monter_dev));
	//
  // for (i = 0; i < monter_num_devices; ++i) { // iteracja od zera przy ustalonym monter_minor nie ma sensu
  //   monter_setup_cdev(&monter_devices[i], i); // nie konfigurowalne
  // }

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
