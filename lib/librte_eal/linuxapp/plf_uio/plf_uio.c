
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/device.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/uio_driver.h>
#include <linux/io.h>
#include <linux/version.h>
#include <linux/slab.h>
#include <linux/acpi.h>
#include <linux/dma-mapping.h>
#include <linux/string.h>
#include <linux/mm.h>  
#include <linux/fs.h>
#include <linux/cdev.h>  
#include <linux/interrupt.h>
#include "compat.h"

void *platform_base;
unsigned long phy_addr;
static unsigned int index;

struct rte_uio_platform_dev {
	struct uio_info info;
	struct platform_device *pdev;
    int cdev_major;
    struct class *dev_class;
};


/**
 * Template to r/w something
 */

// static ssize_t
// show_something(struct device *dev, struct device_attribute *attr,
//                  char *buf)
// {
//     return 0;
// }

// static ssize_t
// store_something(struct device *dev, struct device_attribute *attr,
//                   const char *buf, size_t count)
// {
//     int err = 0;

//     return err ? err : count;
// }

// static DEVICE_ATTR(something, S_IRUGO | S_IWUSR, show_something, store_something);

// static struct attribute *dev_attrs[] = {
//     &dev_attr_something.attr,
//     NULL,
// };

// static const struct attribute_group dev_attr_grp = {
//     .attrs = dev_attrs,
// };

/* Remap platform resources described by index in uio resource n. */
static int
plfuio_setup_iomem(struct platform_device *dev, struct uio_info *info,
		       int n, int index, const char *name)
{
	unsigned long addr, len;
	void *internal_addr;
    struct resource *mem;

	if (n >= ARRAY_SIZE(info->mem))
		return -EINVAL;
    mem = platform_get_resource(dev, IORESOURCE_MEM, index);
	addr = mem->start;
	len = resource_size(mem);
	if (len == 0)
		return -EINVAL;
	
    internal_addr = ioremap(addr, len);
	if (internal_addr == NULL)
		return -1;
	info->mem[n].name = name;
	//info->mem[n].addr = addr;
	info->mem[n].internal_addr = internal_addr;
	info->mem[n].size = len;
	info->mem[n].memtype = UIO_MEM_PHYS;
    printk(KERN_ERR "addr:%08lu,internal_addr:%p\n", addr,internal_addr);
	return 0;
}

/* Get platform port io resources described by index in uio resource n. */
static int
plfuio_setup_ioport(struct platform_device *dev, struct uio_info *info,
		int n, int index, const char *name)
{
	unsigned long addr, len;

	if (n >= ARRAY_SIZE(info->port))
		return -EINVAL;

	addr = platform_resource_start(dev, index);
	len = platform_resource_len(dev, index);
	if (len == 0)
		return -EINVAL;

	info->port[n].name = name;
	info->port[n].start = addr;
	info->port[n].size = len;
	
    /* what porttype it should be? */
    info->port[n].porttype = UIO_PORT_OTHER;

	return 0;
}

/* Unmap previously ioremap'd resources */
static void
plfuio_release_iomem(struct uio_info *info)
{
	int i;

	for (i = 0; i < MAX_UIO_MAPS; i++) {
		if (info->mem[i].internal_addr)
			iounmap(info->mem[i].internal_addr);
	}
}

static int
plfuio_remap_memory(struct platform_device *dev, struct uio_info *info)
{
    int i, ret, iom, iop;
    unsigned long flags;
    unsigned int num_res = dev->num_resources;
	static const char *bar_names[PLATFORM_MAX_RESOURCE + 1]  = {
		"BAR0",
		"BAR1",
		"BAR2",
		"BAR3",
		"BAR4",
		"BAR5",
	};
    
    /* resources are more than we thought */
    if(num_res > PLATFORM_MAX_RESOURCE){
        printk(KERN_EMERG "Too many resource in device: %s\n", dev->name);
        return -ENOENT; 
    }

    iom = 0;
    iop = 0;

    printk(KERN_ERR "There are %d resources\n", num_res);
    for(i=0; i<num_res; i++) {
        if(platform_resource_len(dev, i)!=0 &&
                platform_resource_start(dev, i)!=0) {
            flags = platform_resource_flags(dev, i);

            if(flags & IORESOURCE_MEM){
                ret = plfuio_setup_iomem(dev, info, iom, i, bar_names[i]);
                if(ret!=0)
                    return ret;
                iom++;
            }
            
            
            else if(flags & IORESOURCE_IO) {
                ret = plfuio_setup_ioport(dev, info, iop, i, bar_names[i]);
                if(ret!=0)
                    return ret;
                iop++;
            }
           
        }
    }
    return 0;
}


/**
 * This is the irqcontrol callback to be registered to uio_info.
 * It can be used to disable/enable interrupt from user space processes.
 *
 * @param info
 *  pointer to uio_info.
 * @param irq_state
 *  state value. 1 to enable interrupt, 0 to disable interrupt.
 *
 * @return
 *  - On success, 0.
 *  - On failure, a negative value.
 */
static int
plfuio_irqcontrol(struct uio_info *info, s32 irq_state)
{
	//Do something here.
    return 0;
}

/**
 * This is interrupt handler which will check if the interrupt is for the right device.
 * If yes, disable it here and will be enable later.
 */
static irqreturn_t
plfuio_irqhandler(int irq, struct uio_info *info)
{
	struct rte_uio_platform_dev *udev = info->priv;
    (void) udev;
    //Do something here.

	/* Message signal mode, no share IRQ and automasked */
	return IRQ_HANDLED;
}

int mmapdrv_open(struct inode *inode, struct file *file)
{
    return (0);
}

int mmapdrv_mmap(struct file *file, struct vm_area_struct *vma)
{
    unsigned long size = vma->vm_end - vma->vm_start;

    /* we do not want to have this area swapped out, lock it */
    //vma->vm_flags |= VM_LOCKED;
    // printk(KERN_ERR "phy_addr%08lx\n",phy_addr);
    // {
    //     unsigned int test;
    //     *(unsigned int *)((char *)platform_base+0x14) = 0;
    //     test = *(unsigned int *)((char *)platform_base+0x10);
    //     printk(KERN_ERR "host feature: %08x\n",test);

    //     *(unsigned int *)((char *)platform_base+0x030) = 0;
    //     test = *(unsigned int *)((char *)platform_base+0x034);
    //     printk(KERN_ERR "host feature: %08x\n",test);
    // }
    //phy_addr = virt_to_phys(platform_base);
    if (remap_pfn_range(vma, vma->vm_start, phy_addr>>PAGE_SHIFT, size, vma->vm_page_prot))
    {
        printk(KERN_ERR "remap page range failed\n");
        return - ENXIO;
    }
    return (0);
}

static struct file_operations mmapdrv_fops =
{
    .owner = THIS_MODULE, 
    .mmap = mmapdrv_mmap, 
    .open = mmapdrv_open, 
};

static irqreturn_t vm_interrupt(int irq, void *opaque)
{
    (void)irq;
    (void)opaque;
printk("interrupt\n");    
return IRQ_HANDLED;
}


#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 8, 0)
static int __devinit
#else
static int
#endif
plf_uio_probe(struct platform_device *dev)
{
/*
    (void) plfuio_irqcontrol;
    (void) plfuio_irqhandler;
*/    
    struct rte_uio_platform_dev *udev;
    int err, major;
    struct resource *mem;
    struct device *aeclassdev;
    char devname[60];
    unsigned int irq;
    // void *base;
    printk(KERN_EMERG "hello world!\n");    
    snprintf(devname, 60, "virtio_cdev%d",index);

    //malloc rte_uio_platform_dev
    udev = kzalloc(sizeof(struct rte_uio_platform_dev),GFP_KERNEL);
    if(!udev)
        return -ENOMEM;

    irq = platform_get_irq(dev, 0);
    err = request_irq(irq, vm_interrupt, IRQF_SHARED, dev_name(&dev->dev), udev);
    printk("err:%d\n",err);
     //register cdev
    if ((major = register_chrdev(0, devname, &mmapdrv_fops)) < 0)
    {
        printk(KERN_ERR "virtio_cdev: unable to register character device\n");
        err =  major;
        goto fail_release_udev;
    }
    udev->cdev_major = major;
    udev->dev_class = class_create(THIS_MODULE, devname);
    if (IS_ERR(udev->dev_class)) {
        printk(KERN_ERR "virtio_cdev: unable to class_create\n");
        err = PTR_ERR(udev->dev_class);
        goto fail_unregister_cdev;
    }
    aeclassdev = device_create(udev->dev_class, NULL, MKDEV(udev->cdev_major,
                                0), NULL,devname);
    if (IS_ERR(aeclassdev)) {
        printk(KERN_ERR "virtio_cdev: unable to device_create\n");
        err = PTR_ERR(aeclassdev);
        goto fail_destory_class;
    }
    /* remap IO memory */
  //   err = plfuio_remap_memory(dev, &udev->info);
  //   if(err){
		// printk(KERN_EMERG "REMAP FAILED\n");
  //       goto fail_release_iomem;
  //   }

    (void) plfuio_remap_memory;
    udev->info.name = "plf_uio";
    udev->info.version = "0.1";
    udev->info.handler = plfuio_irqhandler;
    udev->info.irqcontrol = plfuio_irqcontrol;
    udev->info.priv = udev;
    udev->pdev = dev;

    mem = platform_get_resource(dev, IORESOURCE_MEM, 0);
    phy_addr = mem->start;
    platform_base = devm_ioremap(&dev->dev, mem->start, resource_size(mem));

    udev->info.mem[0].name = "resource";
    udev->info.mem[0].addr =  phy_addr;
    udev->info.mem[0].size =  mem->end - phy_addr;
    // udev->info.mem[0].internal_addr = platform_base;
    udev->info.mem[0].memtype = UIO_MEM_PHYS;

    udev->info.mem[1].name = "index";
    udev->info.mem[1].addr =  index;
    udev->info.mem[1].size =  sizeof(int);
    // udev->info.mem[0].internal_addr = platform_base;
    udev->info.mem[1].memtype = UIO_MEM_PHYS;
    index++;

//    err = dma_set_mask_and_coherent(&dev->dev, DMA_BIT_MASK(64));
//    if(err != 0)
//		goto fail_release_iomem; 

  //   err = sysfs_create_group(&dev->dev.kobj, &dev_attr_grp);
  //   if (err != 0)
		// goto fail_release_iomem;  

    err = uio_register_device(&dev->dev, &udev->info);
    if(err != 0)
        goto fail_release_iomem;

    platform_set_drvdata(dev,udev);
    return 0;

// fail_remove_group:
//     sysfs_remove_group(&dev->dev.kobj, &dev_attr_grp);

fail_release_iomem:
	plfuio_release_iomem(&udev->info);
fail_destory_class:
    class_destroy((void *)udev->dev_class);
fail_unregister_cdev:
    unregister_chrdev(major, "virtio_cdev");
fail_release_udev:
    kfree(udev);
    return err;
}

static int
plf_uio_remove(struct platform_device *dev)
{
 
    struct rte_uio_platform_dev *udev = platform_get_drvdata(dev);
    char devname[60];
    int myindex;

    myindex = udev->info.mem[1].addr;
    snprintf(devname, 60, "virtio_cdev%d",myindex);

    class_destroy((void *)udev->dev_class);
    // sysfs_remove_group(&dev->dev.kobj, &dev_attr_grp);
    uio_unregister_device(&udev->info);
    platform_set_drvdata(dev,NULL);
    unregister_chrdev(udev->cdev_major, devname);
    kfree(udev);

    return 0;
}


/* Platform driver */

static struct of_device_id virtio_mmio_match[] = {
        { .compatible = "virtio,mmio", },
        {},
};
MODULE_DEVICE_TABLE(of, virtio_mmio_match);

static struct platform_driver plf_uio_driver = {
    .probe = plf_uio_probe,
    .remove = plf_uio_remove,
    .driver = 
    {
        .name = "plf_uio",
        .owner  = THIS_MODULE,
        .of_match_table = virtio_mmio_match,
    },
};

static int __init
plfuio_init_module(void)
{
    return platform_driver_register(&plf_uio_driver);
}

static void __exit
plfuio_exit_module(void)
{
    platform_driver_unregister(&plf_uio_driver);
}

module_init(plfuio_init_module);
module_exit(plfuio_exit_module);

MODULE_DESCRIPTION("UIO driver for Arm VirtIO");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("LAB 1219");
