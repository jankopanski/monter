#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>

#include <linux/kernel.h>	/* printk() */
#include <linux/slab.h>		/* kmalloc() */
#include <linux/fs.h>		/* everything... */
#include <linux/errno.h>	/* error codes */
#include <linux/types.h>	/* size_t */
#include <linux/proc_fs.h>
#include <linux/fcntl.h>	/* O_ACCMODE */
#include <linux/seq_file.h>
#include <linux/cdev.h>

#include <linux/device.h> /* for struct device */

#include <linux/major.h>

#include <asm/uaccess.h>	/* copy_*_user */

#include <linux/pci.h>

#include "monter.h"
#include "monter_ioctl.h"

// #include <linux/kernel.h> /* printk() */
// #include <linux/module.h>
// #include <linux/slab.h>   /* kmalloc() */
// #include <linux/fs.h>     /* everything... */
// #include <linux/errno.h>  /* error codes */
// #include <linux/types.h>  /* size_t */
// #include <linux/fcntl.h>
// #include <linux/cdev.h>
// #include <linux/tty.h>
// #include <asm/atomic.h>
// #include <linux/list.h>
// #include <linux/sched.h>
// #include <linux/cred.h>

// static
int monter_major = 0;
int monter_minor = 0;
unsigned int monter_num_devices = 2; // 256
// const char *monter_name = "monter";

MODULE_AUTHOR("Jan Kopański");
MODULE_LICENSE("GPL");

// dodać tablicę pci_device_id, MODULE_DEVICE_TABLE

// tablica za ID urządzenia pci
static struct pci_device_id pci_ids[] = {
	{ PCI_DEVICE(0x1af4, 0x10f7), },
	{ 0, }
};

MODULE_DEVICE_TABLE(pci, pci_ids);

struct class *monter_class;

struct monter_dev {
  dev_t devno;
  // struct pci_dev pci_dev;
  struct cdev cdev;
  struct device *dev; // do klasy urządzeń potrzebnych do ich dodania do sysfs
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

static int pci_probe(struct pci_dev *dev, const struct pci_device_id *id) {
	int ret;
	int BAR0 = 0;
	void __iomem *baraddr;
	unsigned int reg;
	printk(KERN_INFO "pci_probe");
	ret = pci_enable_device(dev);
	if (ret < 0) {
		printk(KERN_WARNING "pci_enable_device");
		return ret;
	}
	// ret = pci_request_regions(dev, "monter");
	ret = pci_request_region(dev, 0, "monter");
	printk(KERN_INFO "pci_request_region: %d", ret);
	if (ret == EBUSY) {
		printk(KERN_INFO "EBUSY");
	}
	// if (!ret) {
	// 	printk(KERN_WARNING "pci_request_region");
	// 	return ret;
	// }
	baraddr = pci_iomap(dev, 0, 0);
	if (!baraddr) {
		printk(KERN_WARNING "pci_iomap");
		return 0;
	}
	reg = ioread32(baraddr);
	printk(KERN_INFO "ioread32: %ud", reg);
	iowrite32(0, baraddr);
	printk(KERN_INFO "iowrite32");
	reg = ioread32(baraddr);
	printk(KERN_INFO "ioread32: %ud", reg);
  return 0;
}

static void pci_remove(struct pci_dev *dev) {
  printk(KERN_INFO "pci_remove");
}

// static ?
static struct pci_driver pci_driver = {
  .name = "monter",
  .id_table = pci_ids,
  .probe = pci_probe,
  .remove = pci_remove,
};

void monter_cleanup_module(void) {
  // reset state
  // dealokować cdev
  printk(KERN_INFO "monter_cleanup_module");
}

static void monter_setup_cdev(struct monter_dev *dev, int index) {
  int err;

  dev->devno = MKDEV(monter_major, monter_minor + index);
  cdev_init(&dev->cdev, &monter_fops);
  dev->cdev.owner = THIS_MODULE;
  dev->cdev.ops = &monter_fops;
  err = cdev_add(&dev->cdev, dev->devno, 1);
  if (err) {
    printk(KERN_WARNING "cdev_add");
    return;
  }

  dev->dev = device_create(monter_class, 0, dev->devno, 0, "monter%d", index);
  if (IS_ERR(dev->dev)) {
    printk(KERN_WARNING "device_create");
    dev->dev = 0;
  }
}

int monter_init_module(void) {
  int ret, i;
  dev_t devno;

  ret = alloc_chrdev_region(&devno, monter_minor, monter_num_devices, "monter");
  if (ret < 0) {
    printk(KERN_WARNING "alloc_chrdev_region");
    monter_cleanup_module();
    return ret;
  }
  monter_major = MAJOR(devno);

  monter_class = class_create(THIS_MODULE, "monter");
  if (IS_ERR(monter_class)) {
    ret = PTR_ERR(monter_class);
    printk(KERN_WARNING "class_create");
    monter_cleanup_module();
    return ret;
  }

  monter_devices = kmalloc(monter_num_devices * sizeof(struct monter_dev), GFP_KERNEL);
  if (!monter_devices) {
    ret = - ENOMEM;
    monter_cleanup_module();
    return ret;
  }
  memset(monter_devices, 0, monter_num_devices * sizeof(struct monter_dev));

  for (i = 0; i < monter_num_devices; ++i) { // iteracja od zera przy ustalonym monter_minor nie ma sensu
    monter_setup_cdev(&monter_devices[i], i); // nie konfigurowalne
  }

  ret = pci_register_driver(&pci_driver);
  if (ret < 0) {
    // unregister chrdev region
    printk(KERN_WARNING "pci_register_driver"); // KERN_WARNING, KERN_ERR
    return ret;
  }
  return 0;
}

module_init(monter_init_module);
module_exit(monter_cleanup_module);
