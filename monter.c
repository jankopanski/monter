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
#include <linux/mm.h>
// #include <asm/atomic.h>
#include <asm/page.h>
#include "monter.h"
#include "monter_ioctl.h"

#include <linux/delay.h>

MODULE_AUTHOR("Jan Kopański");
MODULE_LICENSE("GPL");

#define MONTER_MAX_COUNT 256
#define MONTER_MAX_PAGE_NUM 16
#define MONTER_MAX_SIZE (MONTER_MAX_PAGE_NUM * PAGE_SIZE)

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
  void *kern_pages[MONTER_MAX_PAGE_NUM];
  dma_addr_t dma_pages[MONTER_MAX_PAGE_NUM];
  size_t page_num, size;
  int state, operation;
  uint32_t addr_a, addr_b;
};

static irqreturn_t monter_irq_handler(int irq, void *dev) {
  struct monter_dev *monter_dev = dev;
  uint32_t intr;
  intr = ioread32(monter_dev->bar0 + MONTER_INTR);
  // printk(KERN_ALERT "INTR NOTYFY");
  printk(KERN_INFO "interrupt request %u", intr);
  if (!intr) {
    return IRQ_NONE;
  }
  iowrite32(intr, monter_dev->bar0 + MONTER_INTR);

  return IRQ_HANDLED;
}

static void send_commands(struct monter_context *context, uint32_t *cmds, unsigned cmd_num) {
  unsigned i;
  for (i = 0; i < cmd_num; ++i) {
    iowrite32(*cmds, context->mdev->bar0 + MONTER_FIFO_SEND);
    cmds++;
  }
}

static void switch_context(struct monter_context *context) {
  uint32_t i, value;
  printk(KERN_INFO "context_switch");
  for (i = 0; i < 16; ++i) {
    value = MONTER_CMD_PAGE(i, MONTER_CMD_PAGE_ADDR(context->dma_pages[i]), 0);
    printk(KERN_INFO "value: %u %u", i, value);
    iowrite32(value, context->mdev->bar0 + MONTER_FIFO_SEND);
  }
  context->mdev->current_context = context;
}

// static long monter_ioctl(struct file*, unsigned int, unsigned long); // TODO remove
// static int monter_mmap(struct file *, struct vm_area_struct *);

static ssize_t monter_read(struct file *filp, char __user *buf, size_t count, loff_t *f_pos) {
  // struct monter_context *context = filp->private_data;
  // size_t size = 1; //512
  // unsigned long not_copied;
  printk(KERN_INFO "monter_read before: %lld", filp->f_pos);
  // copy_to_user(buf, context->data_area, size);
  // *f_pos = filp->f_pos + size;
  // return size;
  return 0;
}

static int parse_addr_ab(struct monter_context *context, uint32_t *cmd_ptr) {
  uint32_t addr_a = MONTER_SWCMD_ADDR_A(*cmd_ptr), addr_b = MONTER_SWCMD_ADDR_B(*cmd_ptr);
  uint32_t addr_ab = MONTER_CMD_ADDR_AB(addr_a, addr_b, 0);
  if (addr_a >= context->size || addr_b >= context->size) {
    printk(KERN_ALERT "address outside of data area: %u %u %lu", addr_a, addr_b, context->size);
    return -EINVAL;
  }
  printk(KERN_INFO "send_addr_ab");
  *cmd_ptr = addr_ab;
  // iowrite32(addr_ab, context->mdev->bar0 + MONTER_FIFO_SEND);
  context->addr_a = addr_a;
  context->addr_b = addr_b;
  return 0;
}

static int parse_run_op(struct monter_context *context, uint32_t *cmd_ptr, int mult_or_redc) {
  uint32_t size_m1 = MONTER_SWCMD_RUN_SIZE(*cmd_ptr), addr_d = MONTER_SWCMD_ADDR_D(*cmd_ptr);
  uint32_t run_op = 0;
  printk(KERN_INFO "send_run_op: %d", mult_or_redc);
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
  if (mult_or_redc == 0) {
    if (context->addr_a + size_m1 >= context->size) {
      printk(KERN_ALERT "number under A address is outside of data area: %u %lu",
      context->addr_a + size_m1, context->size);
      return -EINVAL;
    }
    run_op = MONTER_CMD_RUN_MULT(size_m1, addr_d, 0); // TODO NOTYFY
  }
  else if (mult_or_redc == 1) {
    run_op = MONTER_CMD_RUN_REDC(size_m1, addr_d, 0);
  }
  else {
    printk(KERN_ALERT "send_run_op");
    return -EINVAL;
  }
  *cmd_ptr = run_op;
  // iowrite32(run_op, context->mdev->bar0 + MONTER_FIFO_SEND);
  printk(KERN_INFO "send_run_op end");
  return 0;
}

static long monter_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
  size_t size = (size_t) arg;
  struct monter_context *context = filp->private_data;
  unsigned i;
  printk(KERN_INFO "monter_ioctl");
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
        printk(KERN_INFO "dma_alloc_coherent pages: %p %llu", context->kern_pages[i], context->dma_pages[i]);
        if (IS_ERR_OR_NULL(context->kern_pages[i])) {
          printk(KERN_ALERT "dma_alloc_coherent: %p %llu", context->kern_pages[i], context->dma_pages[i]);
          return PTR_ERR(context->kern_pages[i]); // TODO inny błąd
        }
      }
      context->state = 1;
      return 0;
    default:
      return -ENOTTY;
  }
}

static int monter_mmap_fault(struct vm_area_struct *vma, struct vm_fault *vmf) {
  struct monter_context *context = vma->vm_private_data;
  struct page *page;
  unsigned page_num = vmf->pgoff;
  long ret;
  printk(KERN_INFO "MONTER FAULT: %p %llu", context->kern_pages[page_num], context->dma_pages[page_num]);
  page = virt_to_page(context->kern_pages[page_num]);
  ret = vm_insert_page(vma, vma->vm_start + (page_num << PAGE_SHIFT), page);
  printk(KERN_INFO "monter_fault vm_insert_page: %ld %lu %lu %u %s", ret, vma->vm_start, vma->vm_start + (page_num << PAGE_SHIFT), page_num, (char*)context->kern_pages[page_num]);
  if (IS_ERR_VALUE(ret)) {
    printk(KERN_ALERT "vm_insert_page");
    return VM_FAULT_SIGBUS; // minus
  }
  return VM_FAULT_NOPAGE;
}

static const struct vm_operations_struct monter_vm_ops = {
  .fault = monter_mmap_fault,
};

static int monter_mmap(struct file *flip, struct vm_area_struct *vma) {
  vma->vm_ops = &monter_vm_ops;
  vma->vm_flags |= VM_MIXEDMAP;//VM_RESERVED;
  vma->vm_private_data = flip->private_data;
  printk(KERN_INFO "MONTER MMAP");
  // msleep(100000);
  return 0;
}

static ssize_t monter_write(struct file *filp, const char __user *buf, size_t count, loff_t *f_pos) {
  // TODO sprawdzić uprawnienia
  // TODO czy nie poprawić - rozbić wczytywania na części, bufor na polecenia
  struct monter_context *context = filp->private_data;
  int ret = 0;
  unsigned long read;
  uint32_t cmd_type;//, user_cmd, driver_cmd;
  uint32_t *data, *cmd_ptr;
  unsigned i, cmd_num;
	printk(KERN_INFO "monter_write");
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
    return -EINVAL; // TODO inny return code
  }
  printk(KERN_INFO "monter_write before copy_from_user: %lld %lu", filp->f_pos, count);
  // if (filp->f_pos == count) return 0;
  // printk(KERN_INFO "monter_write before copy");
  read = copy_from_user(data, buf, count);
  if (read) {
    printk(KERN_ALERT "copy_from_user: %lu", read);
    ret = -EINVAL;
    goto fail;
  }
  *f_pos = filp->f_pos + count;
  cmd_ptr = data;
  cmd_num = count / 4;
  printk(KERN_INFO "monter_write before for loop %p %p %u", cmd_ptr, data, *cmd_ptr);
  for (i = 0; i < cmd_num; ++i) {
    // user_cmd = *cmd_ptr;
    cmd_type = MONTER_SWCMD_TYPE(*cmd_ptr);
    printk(KERN_INFO "monter_write for iter %u %u", i, cmd_type);
    switch (cmd_type) {
      case MONTER_SWCMD_TYPE_ADDR_AB:
        ret = parse_addr_ab(context, cmd_ptr);
        if (ret) {
          printk(KERN_ALERT "parse_addr_ab");
          goto fail;
        }
        printk(KERN_INFO "setting context->operation");
        context->operation = 1;
        break;
      case MONTER_SWCMD_TYPE_RUN_MULT:
        if (!context->operation) {
          printk(KERN_ALERT "monter_write MULT without ADDR");
          ret = -EINVAL;
          goto fail;
        };
        ret = parse_run_op(context, cmd_ptr, 0); // TODO dodać makra? na MULT I REDC
        if (ret) {
          printk(KERN_ALERT "parse_run_op MULT");
          goto fail;
        }
        break;
      case MONTER_SWCMD_TYPE_RUN_REDC:
        if (!context->operation) {
          printk(KERN_ALERT "monter_write REDC without ADDR");
          ret = -EINVAL;
          goto fail;
        };
        ret = parse_run_op(context, cmd_ptr, 1);
        if (ret) {
          printk(KERN_ALERT "parse_run_op REDC");
          goto fail;
        }
        break;
      default:
        printk(KERN_ALERT "invalid cmd type");
        ret = -EINVAL;
        goto fail;
    }
    cmd_ptr++;
    printk(KERN_INFO "monter_write for end iter %u", i);
  }
  printk(KERN_INFO "monter_write before context switch: %p %p", context->mdev->current_context, context);
  if (context->mdev->current_context != context) {
    printk(KERN_ALERT "DOING CONTEXT SWITCH");
    switch_context(context);
  }
  // data[cmd_num] = MONTER_CMD_ADDR_AB(0, 0, 1);
  printk(KERN_INFO "before send_commands");
  send_commands(context, data, cmd_num);
  // kfree(data); TODO zwalnianie pamięci
  printk(KERN_INFO "monter_write end");
  return count;
fail:
  printk(KERN_INFO "monter_write fail");
  kfree(data);
  return ret;
}

static int monter_fsync(struct file *file, loff_t start, loff_t end,
			  int datasync) {
  msleep(1000);
  return 0;
}

static int monter_open(struct inode *inode, struct file *filp) {
  int major = MAJOR(inode->i_rdev), minor = MINOR(inode->i_rdev);
  struct monter_dev *monter_dev;
  struct monter_context *context;
  int i;
  printk(KERN_INFO "monter_open");
  monter_dev = container_of(inode->i_cdev, struct monter_dev, cdev);
  context = kmalloc(sizeof(struct monter_context), GFP_KERNEL);
  if (!context) {
    printk(KERN_ALERT "kmalloc %d:%d", major, minor);
    return -ENOMEM;
  }
  context->mdev = monter_dev;
  for (i = 0; i < 16; ++i) { // TODO MAX PAGE NUM
    context->kern_pages[i] = NULL;
    context->dma_pages[i] = 0;
  }
  context->page_num = 0;
  context->size = 0;
  context->state = 0;
  context->operation = 0;
  monter_dev->current_context = NULL;
  filp->private_data = context;
  return 0;
}

static int monter_release(struct inode *inode, struct file *filp) {
  struct monter_context *context = filp->private_data;
  int i;
	printk(KERN_INFO "monter_release");
  if (context->state) {
    for (i = 0; i < context->page_num; ++i) {
      if (context->kern_pages[i]) {
        dma_free_coherent(&context->mdev->pdev->dev, PAGE_SIZE, context->kern_pages[i], context->dma_pages[i]);
      }
    }
  }
  kfree(context);
	return 0;
}

struct file_operations monter_fops = {
  .owner = THIS_MODULE,
  .read = monter_read,
  .write = monter_write,
  .unlocked_ioctl = monter_ioctl,
  .mmap = monter_mmap,
  .open = monter_open,
  .release = monter_release,
  .fsync = monter_fsync,
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
	if (IS_ERR_VALUE(ret)) { // ret == EBUSY
		printk(KERN_ALERT "pci_request_region");
		goto err_pci_region;
	}

	monter_dev->bar0 = pci_iomap(dev, 0, 0);
	if (IS_ERR(monter_dev->bar0)) {
		printk(KERN_ALERT "pci_iomap");
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
    printk(KERN_ALERT "dma_set_mask_and_coherent");
    goto err_dma_mask;
  }

	ret = request_irq(dev->irq, monter_irq_handler, IRQF_SHARED, "monter", monter_dev);
  if (IS_ERR_VALUE(ret)) {
    printk(KERN_ALERT "request_irq");
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
		printk(KERN_ALERT "idr_alloc");
		ret = minor;
		goto err_idr;
	}

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

// tablica z ID urządzenia pci
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
	// int i;

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
