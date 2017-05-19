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

int monter_major = 0;
int monter_minor = 0;
unsigned int monter_num_devices = 2; // 256
// const char *monter_name = "monter";

MODULE_AUTHOR("Jan Kopański");
MODULE_LICENSE("GPL");

struct class *monter_class;

struct monter_dev {
  dev_t devno;
  struct cdev cdev;
  struct device *dev;
};

struct monter_dev *monter_devices;

ssize_t monter_read(struct file *filp, char __user *buf, size_t count, loff_t *f_pos) {
  return 0;
}

ssize_t scull_write(struct file *filp, const char __user *buf, size_t count, loff_t *f_pos) {
  return 0;
}

long scull_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
  return 0;
}

int mmap(struct file *flip, struct vm_area_struct *vm_area) {
  return 0;
}

int monter_open(struct inode *inode, struct file *filp) {
  return 0;
}

int scull_release(struct inode *inode, struct file *filp) {
	return 0;
}

// release - close
struct file_operations monter_fops = {
  owner: THIS_MODULE,
  // read: monter_read,
  // write: monter_write,
  // ioctl: monter_ioctl,
  // mmap: monter_mmap,
  // open: monter_open,
  // release: monter_release,
  // fsync: monter_fsync,
};

void monter_cleanup_module(void) {
  // reset state
  printk(KERN_WARNING "cleanup");
}

static void monter_setup_cdev(struct monter_dev *dev, int index) {
  int err;

  dev->devno = MKDEV(monter_major, monter_minor + index);
  cdev_init(&dev->cdev, &monter_fops);
  dev->cdev.owner = THIS_MODULE;
  dev->cdev.ops = &monter_fops;
  err = cdev_add(&dev->cdev, dev->devno, 1);
  if (err) {
    printk(KERN_NOTICE "cdev_add");
    return;
  }

  dev->dev = device_create(monter_class, 0, dev->devno, 0, "monter%d", index);
  if (IS_ERR(dev->dev)) {
    printk(KERN_NOTICE "device_create");
    dev->dev = 0;
  }
}

int monter_init_module(void) {
  int result, i;
  dev_t dev;

  result = alloc_chrdev_region(&dev, monter_minor, monter_num_devices, "monter");
  monter_major = MAJOR(dev);
  if (result < 0) {
    printk(KERN_WARNING "alloc_chrdev_region");
    monter_cleanup_module();
    return result;
  }

  monter_class = class_create(THIS_MODULE, "monter");
  if (IS_ERR(monter_class)) {
    result = PTR_ERR(monter_class);
    printk(KERN_WARNING "class_create");
    monter_cleanup_module();
    return result;
  }

  monter_devices = kmalloc(monter_num_devices * sizeof(struct monter_dev), GFP_KERNEL);
  if (!monter_devices) {
    result = - ENOMEM;
    monter_cleanup_module();
    return result;
  }
  memset(monter_devices, 0, monter_num_devices * sizeof(struct monter_dev));

  for (i = 0; i < monter_num_devices; ++i) {
    monter_setup_cdev(&monter_devices[i], i);
  }
  return 0;
}

module_init(monter_init_module);
module_exit(monter_cleanup_module);
