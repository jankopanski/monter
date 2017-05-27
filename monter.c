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
#include <linux/mm.h>
#include <asm/page.h>
#include "monter.h"
#include "monter_ioctl.h"

MODULE_AUTHOR("Jan Kopański");
MODULE_LICENSE("GPL");

#define MONTER_MAX_COUNT 256
#define MONTER_MAX_PAGE_NUM 16
#define MONTER_MAX_SIZE (MONTER_MAX_PAGE_NUM * PAGE_SIZE)
#define MONTER_MULT 0
#define MONTER_REDC 1

static struct class *monter_class = NULL;
dev_t dev_base = 0;
int monter_major = 0;
static DEFINE_IDR(monter_idr);

static LIST_HEAD(device_list_begin);
static DEFINE_SPINLOCK(device_list_lock);

struct cmd_batch {
  uint32_t cmds[32];
  int num, end;
  struct monter_context *context;
  struct list_head queue;
};

struct monter_dev {
  struct pci_dev *pdev;
  struct cdev cdev;
	void __iomem *bar0;
  struct monter_context *current_context;
  struct list_head cmd_queue;
  struct list_head device_list;
  struct mutex write_mutex;
  spinlock_t slock;
};

// struct monter_dev *monter_devices;

struct monter_context {
  struct monter_dev *mdev;
  void *kern_pages[MONTER_MAX_PAGE_NUM];
  dma_addr_t dma_pages[MONTER_MAX_PAGE_NUM];
  size_t page_num, size;
  int state, operation, incr_batch_num;
  unsigned batch_num, done_batch_num;
  uint32_t addr_a, addr_b;
  wait_queue_head_t fsync_wait_queue;
};

static void send_commands(struct monter_context *context, uint32_t *cmds, unsigned cmd_num) {
  unsigned i;
  for (i = 0; i < cmd_num; ++i) {
    iowrite32(*cmds, context->mdev->bar0 + MONTER_FIFO_SEND);
    cmds++;
  }
}

static void switch_context(struct monter_context *context) {
  uint32_t i, value;
  for (i = 0; i < MONTER_MAX_PAGE_NUM; ++i) {
    value = MONTER_CMD_PAGE(i, MONTER_CMD_PAGE_ADDR(context->dma_pages[i]), 0);
    iowrite32(value, context->mdev->bar0 + MONTER_FIFO_SEND);
  }
  context->mdev->current_context = context;
}

static irqreturn_t monter_irq_handler(int irq, void *dev) {
  struct monter_dev *monter_dev, *list_dev;
  struct list_head *ptr, *device_ptr;
  struct cmd_batch *batch;
  uint32_t intr;
  unsigned long flags, device_list_flags;
  int is_device_member = 0;
  printk(KERN_INFO "monter_irq_handler begin");
  spin_lock_irqsave(&device_list_lock, device_list_flags);
  list_for_each(device_ptr, &device_list_begin) {
    if (device_ptr != &device_list_begin) {
      list_dev = list_entry(device_ptr, struct monter_dev, device_list);
      if (list_dev == dev) is_device_member = 1;
    }
  }
  spin_unlock_irqrestore(&device_list_lock, device_list_flags);
  if (!is_device_member) return IRQ_NONE;
  monter_dev = dev;
  spin_lock_irqsave(&monter_dev->slock, flags);
  intr = ioread32(monter_dev->bar0 + MONTER_INTR);
  if (!intr) {
    spin_unlock_irqrestore(&monter_dev->slock, flags);
    return IRQ_NONE;
  }
  iowrite32(intr, monter_dev->bar0 + MONTER_INTR);
  if (intr & 0x6) {
    spin_unlock_irqrestore(&monter_dev->slock, flags);
    return IRQ_HANDLED;
  }
  if (monter_dev->current_context && monter_dev->current_context->incr_batch_num) {
    monter_dev->current_context->incr_batch_num = 0;
    monter_dev->current_context->done_batch_num++;
    wake_up_interruptible(&monter_dev->current_context->fsync_wait_queue);
  }
  if (!list_empty(&monter_dev->cmd_queue)) {
    ptr = monter_dev->cmd_queue.next;
    batch = list_entry(ptr, struct cmd_batch, queue);
    if (monter_dev->current_context != batch->context) {
      switch_context(batch->context);
      iowrite32(MONTER_CMD_COUNTER(0, 1), monter_dev->bar0 + MONTER_FIFO_SEND);
    }
    else {
      monter_dev->current_context->incr_batch_num = 1;
      send_commands(monter_dev->current_context, batch->cmds, batch->num);
      list_del(ptr);
      kfree(batch);
    }
  }
  spin_unlock_irqrestore(&monter_dev->slock, flags);
  printk(KERN_INFO "interrupt request end");
  return IRQ_HANDLED;
}

static int parse_addr_ab(struct monter_context *context, uint32_t *cmd_ptr, unsigned notify) {
  uint32_t addr_a = MONTER_SWCMD_ADDR_A(*cmd_ptr), addr_b = MONTER_SWCMD_ADDR_B(*cmd_ptr);
  uint32_t addr_ab = MONTER_CMD_ADDR_AB(addr_a, addr_b, notify);
  if (addr_a >= context->size || addr_b >= context->size) {
    printk(KERN_ALERT "address outside of data area: %u %u %lu", addr_a, addr_b, context->size);
    return -EINVAL;
  }
  *cmd_ptr = addr_ab;
  context->addr_a = addr_a;
  context->addr_b = addr_b;
  return 0;
}

static int parse_run_op(struct monter_context *context, uint32_t *cmd_ptr, int mult_or_redc, unsigned notify) {
  uint32_t size_m1 = MONTER_SWCMD_RUN_SIZE(*cmd_ptr), addr_d = MONTER_SWCMD_ADDR_D(*cmd_ptr);
  uint32_t run_op = 0;
  if (*cmd_ptr & 1<<17) {
    printk(KERN_ALERT "send_run_op bit 17");
    return -EINVAL;
  }
  if (addr_d >= context->size) {
    printk(KERN_ALERT "result address outside of data area: %u %lu", addr_d, context->size);
    return -EINVAL;
  }
  if (context->addr_b + size_m1 >= context->size) {
    printk(KERN_ALERT "number under B address is outside of data area: %u %lu",
    context->addr_b + size_m1, context->size);
    return -EINVAL;
  }
  if (mult_or_redc == MONTER_MULT) {
    if (context->addr_a + size_m1 >= context->size) {
      printk(KERN_ALERT "number under A address is outside of data area: %u %lu",
      context->addr_a + size_m1, context->size);
      return -EINVAL;
    }
    run_op = MONTER_CMD_RUN_MULT(size_m1, addr_d, notify);
  }
  else if (mult_or_redc == MONTER_REDC) {
    run_op = MONTER_CMD_RUN_REDC(size_m1, addr_d, notify);
  }
  else {
    printk(KERN_ALERT "send_run_op");
    return -EINVAL;
  }
  *cmd_ptr = run_op;
  return 0;
}

static long monter_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
  size_t size = (size_t) arg;
  struct monter_context *context = filp->private_data;
  unsigned i;
  switch (cmd) {
    case MONTER_IOCTL_SET_SIZE:
      if (context->state) {
        printk(KERN_ALERT "context->state: %u", context->state);
        return -EINVAL;
      }
      if (size <= 0 || size > MONTER_MAX_SIZE || size % PAGE_SIZE != 0) {
        printk(KERN_ALERT "ioctl size: %lu", size);
        return -EINVAL;
      }
      context->size = size;
      context->page_num = size / PAGE_SIZE;
      for (i = 0; i < context->page_num; ++i) {
        context->kern_pages[i] = dma_alloc_coherent(&context->mdev->pdev->dev, PAGE_SIZE, &(context->dma_pages[i]), GFP_KERNEL); // TODO PAGE_SIZE
        if (IS_ERR_OR_NULL(context->kern_pages[i])) {
          printk(KERN_ALERT "dma_alloc_coherent: %p %llu", context->kern_pages[i], context->dma_pages[i]);
          return PTR_ERR(context->kern_pages[i]);
        }
      }
      context->state = 1;
      return 0;
      printk(KERN_INFO "monter_ioctl");
    default:
      return -ENOTTY;
  }
}

static int monter_mmap_fault(struct vm_area_struct *vma, struct vm_fault *vmf) {
  struct monter_context *context = vma->vm_private_data;
  struct page *page;
  unsigned page_num = vmf->pgoff;
  long ret;
  page = virt_to_page(context->kern_pages[page_num]);
  ret = vm_insert_page(vma, vma->vm_start + (page_num << PAGE_SHIFT), page);
  if (IS_ERR_VALUE(ret)) {
    printk(KERN_ALERT "vm_insert_page");
    return VM_FAULT_SIGBUS;
  }
  printk(KERN_INFO "monter_mmap_fault");
  return VM_FAULT_NOPAGE;
}

static const struct vm_operations_struct monter_vm_ops = {
  .fault = monter_mmap_fault,
};

static int monter_mmap(struct file *flip, struct vm_area_struct *vma) {
  vma->vm_ops = &monter_vm_ops;
  vma->vm_flags |= VM_MIXEDMAP;
  vma->vm_private_data = flip->private_data;
  printk(KERN_INFO "monter_mmap");
  return 0;
}

static ssize_t monter_write(struct file *filp, const char __user *buf, size_t count, loff_t *f_pos) {
  struct monter_context *context = filp->private_data;
  struct cmd_batch *batch;
  int ret = -EINVAL;
  unsigned long read, flags;
  uint32_t cmd_type, status;
  uint32_t *data, *cmd_ptr;
  unsigned i, cmd_num, notify;
  // mutex_lock(&(context->mdev->write_mutex));
	printk(KERN_INFO "monter_write begin");
  if (context->state != 1) {
    printk(KERN_ALERT "monter_write state: %d", context->state);
    return -EINVAL;
  }
  if (count % 4) {
    printk(KERN_ALERT "monter_write count: %lu", count);
    return -EINVAL;
  }
  data = kmalloc(count + 4, GFP_KERNEL);
  if (!data) {
    printk(KERN_ALERT "monter_write data allocation");
    return -EINVAL;
  }
  printk(KERN_INFO "monter_write before copy_from_user: %lld %lu", filp->f_pos, count);
  read = copy_from_user(data, buf, count);
  if (read) {
    printk(KERN_ALERT "copy_from_user: %lu", read);
    goto err_data;
  }
  *f_pos = filp->f_pos + count;
  cmd_ptr = data;
  cmd_num = count / 4;
  printk(KERN_INFO "monter_write before for loop %p %p %u", cmd_ptr, data, *cmd_ptr);
  for (i = 0; i < cmd_num; ++i) {
    cmd_type = MONTER_SWCMD_TYPE(*cmd_ptr);
    notify = i % 32 == 31 ? 1 : 0;
    printk(KERN_INFO "monter_write for iter %u %u", i, cmd_type);
    switch (cmd_type) {
      case MONTER_SWCMD_TYPE_ADDR_AB:
        ret = parse_addr_ab(context, cmd_ptr, notify);
        if (ret) {
          printk(KERN_ALERT "parse_addr_ab");
          goto err_data;
        }
        context->operation = 1;
        break;
      case MONTER_SWCMD_TYPE_RUN_MULT:
        if (!context->operation) {
          printk(KERN_ALERT "monter_write MULT without ADDR");
          goto err_data;
        };
        ret = parse_run_op(context, cmd_ptr, MONTER_MULT, notify);
        if (ret) {
          printk(KERN_ALERT "parse_run_op MULT");
          goto err_data;
        }
        break;
      case MONTER_SWCMD_TYPE_RUN_REDC:
        if (!context->operation) {
          printk(KERN_ALERT "monter_write REDC without ADDR");
          goto err_data;
        };
        ret = parse_run_op(context, cmd_ptr, MONTER_REDC, notify);
        if (ret) {
          printk(KERN_ALERT "parse_run_op REDC");
          goto err_data;
        }
        break;
      default:
        printk(KERN_ALERT "invalid cmd type");
        goto err_data;
    }
    cmd_ptr++;
  }
  printk(KERN_INFO "monter_write before context switch: %p %p", context->mdev->current_context, context);
  data[cmd_num] = MONTER_CMD_COUNTER(0, 1);
  mutex_lock(&(context->mdev->write_mutex));
  printk(KERN_INFO "inside spinlock");
  for (i = 0; i <= cmd_num;) {
    batch = kmalloc(sizeof(struct cmd_batch), GFP_KERNEL);
    if (!batch) {
      printk(KERN_ALERT "monter_write batch allocation");
      goto err_mutex;
    }
    batch->context = context;
    if (cmd_num + 1 - i <= 32) {
      batch->num = cmd_num + 1 - i;
      batch->end = 1;
    }
    else {
      batch->num = 32;
      batch->end = 0;
    }
    memcpy(batch->cmds, data + i, batch->num * 4);
    printk(KERN_INFO "before INIT_LIST_HEAD");
    spin_lock_irqsave(&context->mdev->slock, flags);
    INIT_LIST_HEAD(&batch->queue);
    printk(KERN_INFO "before list_add_tail");
    list_add_tail(&batch->queue, &context->mdev->cmd_queue);
    spin_unlock_irqrestore(&context->mdev->slock, flags);
    context->batch_num++;
    i += batch->num;
  }
  printk(KERN_INFO "after spinlock loop");
  spin_lock_irqsave(&context->mdev->slock, flags);
  status = ioread32(context->mdev->bar0 + MONTER_STATUS);
  if (!(status & 0x3)) {
    iowrite32(MONTER_CMD_COUNTER(0, 1), context->mdev->bar0 + MONTER_FIFO_SEND);
  }
  spin_unlock_irqrestore(&context->mdev->slock, flags);
  mutex_unlock(&(context->mdev->write_mutex));
  kfree(data);
  printk(KERN_INFO "monter_write end");
  return count;
err_mutex:
  mutex_unlock(&(context->mdev->write_mutex));
err_data:
  kfree(data);
  return ret;
}

static int monter_fsync(struct file *filp, loff_t start, loff_t end, int datasync) {
  struct monter_context *context = filp->private_data;
  wait_event_interruptible(context->fsync_wait_queue, context->batch_num == context->done_batch_num);
  printk(KERN_INFO "monter_fsync");
  return 0;
}

static int monter_open(struct inode *inode, struct file *filp) {
  int major = MAJOR(inode->i_rdev), minor = MINOR(inode->i_rdev);
  struct monter_dev *monter_dev;
  struct monter_context *context;
  int i;
  monter_dev = container_of(inode->i_cdev, struct monter_dev, cdev);
  context = kmalloc(sizeof(struct monter_context), GFP_KERNEL);
  if (!context) {
    printk(KERN_ALERT "kmalloc %d:%d", major, minor);
    return -ENOMEM;
  }
  context->mdev = monter_dev;
  for (i = 0; i < MONTER_MAX_PAGE_NUM; ++i) {
    context->kern_pages[i] = NULL;
    context->dma_pages[i] = 0;
  }
  context->page_num = 0;
  context->size = 0;
  context->state = 0;
  context->operation = 0;
  context->batch_num = 0;
  context->done_batch_num = 0;
  context->incr_batch_num = 0;
  init_waitqueue_head(&context->fsync_wait_queue);
  filp->private_data = context;
  printk(KERN_INFO "monter_open");
  return 0;
}

static int monter_release(struct inode *inode, struct file *filp) {
  struct monter_context *context = filp->private_data;
  struct list_head *pos, *next;
  struct cmd_batch *batch;
  int i;
  unsigned long flags;
	printk(KERN_INFO "monter_release begin");
  spin_lock_irqsave(&context->mdev->slock, flags);
  if (context->mdev->current_context == context) {
    context->mdev->current_context = NULL;
  }
  // printk(KERN_INFO "before list_for_each_safe");
  list_for_each_safe(pos, next, &context->mdev->cmd_queue) {
    if (pos != &context->mdev->cmd_queue) {
      batch = list_entry(pos, struct cmd_batch, queue);
      if (batch->context == context) {
        list_del(pos);
        kfree(batch);
      }
    }
  }
  spin_unlock_irqrestore(&context->mdev->slock, flags);
  if (context->state) {
    for (i = 0; i < context->page_num; ++i) {
      if (context->kern_pages[i]) {
        dma_free_coherent(&context->mdev->pdev->dev, PAGE_SIZE, context->kern_pages[i], context->dma_pages[i]);
      }
    }
  }
  kfree(context);
  printk(KERN_INFO "after release");
	return 0;
}

struct file_operations monter_fops = {
  .owner = THIS_MODULE,
  .write = monter_write,
  .unlocked_ioctl = monter_ioctl,
  .mmap = monter_mmap,
  .open = monter_open,
  .release = monter_release,
  .fsync = monter_fsync,
};

static int monter_probe(struct pci_dev *dev, const struct pci_device_id *id) {
	long ret;
  unsigned long flags;
	struct monter_dev *monter_dev;
	struct device *device;
	int minor;

	monter_dev = kmalloc(sizeof(struct monter_dev), GFP_KERNEL);
	if (!monter_dev) {
		printk(KERN_ALERT "kmalloc");
		return -ENOMEM;
	}
	monter_dev->pdev = dev;
	cdev_init(&monter_dev->cdev, &monter_fops);

	ret = pci_enable_device(dev);
	if (IS_ERR_VALUE(ret)) {
		printk(KERN_ALERT "pci_enable_device");
		goto err_pci_enable;
	}

	ret = pci_request_region(dev, 0, "monter");
	if (IS_ERR_VALUE(ret)) {
		printk(KERN_ALERT "pci_request_region");
		goto err_pci_region;
	}

	monter_dev->bar0 = pci_iomap(dev, 0, 0);
	if (IS_ERR(monter_dev->bar0)) {
		printk(KERN_ALERT "pci_iomap");
		ret = PTR_ERR(monter_dev->bar0);
		goto err_pci_iomap;
	}

  iowrite32(3, monter_dev->bar0 + MONTER_RESET);
  iowrite32(7, monter_dev->bar0 + MONTER_INTR);
  iowrite32(7, monter_dev->bar0 + MONTER_INTR_ENABLE);
  iowrite32(1, monter_dev->bar0 + MONTER_ENABLE);

	pci_set_master(dev);
	ret = dma_set_mask_and_coherent(&dev->dev, DMA_BIT_MASK(32));
  if (IS_ERR_VALUE(ret)) {
    printk(KERN_ALERT "dma_set_mask_and_coherent");
    goto err_dma_mask;
  }

  INIT_LIST_HEAD(&monter_dev->cmd_queue);
  spin_lock_init(&monter_dev->slock);
  mutex_init(&monter_dev->write_mutex);

	ret = request_irq(dev->irq, monter_irq_handler, IRQF_SHARED, "monter", monter_dev);
  if (IS_ERR_VALUE(ret)) {
    printk(KERN_ALERT "request_irq");
    goto err_irq;
  }

	minor = idr_alloc(&monter_idr, monter_dev, 0, MONTER_MAX_COUNT, GFP_KERNEL);
	if (IS_ERR_VALUE((long)minor)) {
		printk(KERN_ALERT "idr_alloc");
		ret = minor;
		goto err_idr;
	}

  monter_dev->current_context = NULL;

  INIT_LIST_HEAD(&monter_dev->device_list);
  spin_lock_irqsave(&device_list_lock, flags);
  list_add(&monter_dev->device_list, &device_list_begin);
  spin_unlock_irqrestore(&device_list_lock, flags);

	ret = cdev_add(&monter_dev->cdev, dev_base + minor, 1);
	if (IS_ERR_VALUE(ret)) {
		printk(KERN_ALERT "cdev_add");
		goto err_cdev;
	}

	device = device_create(monter_class, &dev->dev, monter_dev->cdev.dev, monter_dev, "monter%d", minor);
	if (IS_ERR(device)) {
		printk(KERN_ALERT "device_create");
		ret = PTR_ERR(device);
		goto err_dev;
	}

	pci_set_drvdata(dev, monter_dev);

  printk(KERN_INFO "pci_probe");
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
  unsigned long flags;

  spin_lock_irqsave(&device_list_lock, flags);
  list_del(&monter_dev->device_list);
  spin_unlock_irqrestore(&device_list_lock, flags);

  iowrite32(3, monter_dev->bar0 + MONTER_RESET);
  device_destroy(monter_class, monter_dev->cdev.dev);
  cdev_del(&monter_dev->cdev);
  idr_remove(&monter_idr, MINOR(monter_dev->cdev.dev));
  free_irq(dev->irq, monter_dev);
  pci_iounmap(dev, monter_dev->bar0);
  pci_release_region(dev, 0);
  pci_disable_device(dev);
  kfree(monter_dev);
  printk(KERN_INFO "monter_remove");
}

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

static int __init monter_init(void) {
  long ret = -EINVAL;

	monter_class = class_create(THIS_MODULE, "monter");
  if (IS_ERR(monter_class)) {
    printk(KERN_ALERT "class_create");
    return PTR_ERR(monter_class);
  }

  ret = alloc_chrdev_region(&dev_base, 0, MONTER_MAX_COUNT, "monter");
  if (IS_ERR_VALUE(ret)) {
    printk(KERN_ALERT "alloc_chrdev_region");
		goto err_class;
  }
  monter_major = MAJOR(dev_base);

  ret = pci_register_driver(&monter_driver);
  if (IS_ERR_VALUE(ret)) {
    printk(KERN_ALERT "pci_register_driver");
    goto err_chrdev;
  }
  printk(KERN_INFO "monter_init");
  return 0;

err_chrdev:
	unregister_chrdev_region(dev_base, MONTER_MAX_COUNT);
err_class:
	class_destroy(monter_class);
	return ret;
}

static void __exit monter_exit(void) {
	pci_unregister_driver(&monter_driver);
	unregister_chrdev_region(dev_base, MONTER_MAX_COUNT);
	class_destroy(monter_class);
  printk(KERN_INFO "monter_exit");
}

module_init(monter_init);
module_exit(monter_exit);
