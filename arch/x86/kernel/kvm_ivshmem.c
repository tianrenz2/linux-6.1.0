/*
 * drivers/char/kvm_ivshmem.c - driver for KVM Inter-VM shared memory PCI device
 *
 * Copyright 2009 Cam Macdonell <cam@cs.ualberta.ca>
 *
 * Based on cirrusfb.c and 8139cp.c:
 *         Copyright 1999-2001 Jeff Garzik
 *         Copyright 2001-2004 Jeff Garzik
 *
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/proc_fs.h>
#include <linux/hardirq.h>
#include <asm/uaccess.h>
#include <linux/interrupt.h>

#include <asm/kernel_rr.h>


#define TRUE 1
#define FALSE 0
#define KVM_IVSHMEM_DEVICE_MINOR_NUM 0

enum {
	/* KVM Inter-VM shared memory device register offsets */
	IntrMask        = 0x00,    /* Interrupt Mask */
	IntrStatus      = 0x04,    /* Interrupt Status */
	IVPosition      = 0x08,    /* VM ID */
	Doorbell        = 0x0c,    /* Doorbell */
};

typedef struct kvm_ivshmem_device {
	void __iomem * regs;

	void * base_addr;

	unsigned int regaddr;
	unsigned int reg_size;

	unsigned int ioaddr;
	unsigned long ioaddr_size;
	unsigned int irq;

	struct pci_dev *dev;
	char (*msix_names)[256];
	struct msix_entry *msix_entries;
	int nvectors;

	bool		 enabled;

} kvm_ivshmem_device;

static int event_num;
static struct semaphore sema;
static wait_queue_head_t wait_queue;

static bool inited_queue = false;

static kvm_ivshmem_device kvm_ivshmem_dev;

static int device_major_nr;

static int kvm_ivshmem_mmap(struct file *, struct vm_area_struct *);
static int kvm_ivshmem_open(struct inode *, struct file *);
static int kvm_ivshmem_release(struct inode *, struct file *);
static ssize_t kvm_ivshmem_read(struct file *, char *, size_t, loff_t *);
static ssize_t kvm_ivshmem_write(struct file *, const char *, size_t, loff_t *);
static loff_t kvm_ivshmem_lseek(struct file * filp, loff_t offset, int origin);

enum ivshmem_ioctl { set_sema, down_sema, empty, wait_event, wait_event_irq, read_ivposn, read_livelist, sema_irq };

static const struct file_operations kvm_ivshmem_ops = {
	.owner   = THIS_MODULE,
	.open	= kvm_ivshmem_open,
	.mmap	= kvm_ivshmem_mmap,
	.read	= kvm_ivshmem_read,
	.write   = kvm_ivshmem_write,
	.llseek  = kvm_ivshmem_lseek,
	.release = kvm_ivshmem_release,
};

static struct pci_device_id kvm_ivshmem_id_table[] = {
	{ 0x1af4, 0x1110, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0 },
	{ 0 },
};
MODULE_DEVICE_TABLE (pci, kvm_ivshmem_id_table);

static void kvm_ivshmem_remove_device(struct pci_dev* pdev);
static int kvm_ivshmem_probe_device (struct pci_dev *pdev,
						const struct pci_device_id * ent);

static struct pci_driver kvm_ivshmem_pci_driver = {
	.name		= "kvm-shmem",
	.id_table	= kvm_ivshmem_id_table,
	.probe	   = kvm_ivshmem_probe_device,
	.remove	  = kvm_ivshmem_remove_device,
};


static ssize_t kvm_ivshmem_read(struct file * filp, char * buffer, size_t len,
						loff_t * poffset)
{

	int bytes_read = 0;
	unsigned long offset;

	offset = *poffset;

	if (!kvm_ivshmem_dev.base_addr) {
		printk(KERN_ERR "KVM_IVSHMEM: cannot read from ioaddr (NULL)\n");
		return 0;
	}

	if (len > kvm_ivshmem_dev.ioaddr_size - offset) {
		len = kvm_ivshmem_dev.ioaddr_size - offset;
	}

	if (len == 0) return 0;

	bytes_read = copy_to_user(buffer, kvm_ivshmem_dev.base_addr+offset, len);
	if (bytes_read > 0) {
		return -EFAULT;
	}

	*poffset += len;
	return len;
}

static loff_t kvm_ivshmem_lseek(struct file * filp, loff_t offset, int origin)
{

	loff_t retval = -1;

	switch (origin) {
		case 1:
			offset += filp->f_pos;
            break;
		case 0:
			retval = offset;
			if (offset > kvm_ivshmem_dev.ioaddr_size) {
				offset = kvm_ivshmem_dev.ioaddr_size;
			}
			filp->f_pos = offset;
	}

	return retval;
}

static ssize_t kvm_ivshmem_write(struct file * filp, const char * buffer,
					size_t len, loff_t * poffset)
{

	int bytes_written = 0;
	unsigned long offset;

	offset = *poffset;

//	printk(KERN_INFO "KVM_IVSHMEM: trying to write\n");
	if (!kvm_ivshmem_dev.base_addr) {
		printk(KERN_ERR "KVM_IVSHMEM: cannot write to ioaddr (NULL)\n");
		return 0;
	}

	if (len > kvm_ivshmem_dev.ioaddr_size - offset) {
		len = kvm_ivshmem_dev.ioaddr_size - offset;
	}

//	printk(KERN_INFO "KVM_IVSHMEM: len is %u\n", (unsigned) len);
	if (len == 0) return 0;

	bytes_written = copy_from_user(kvm_ivshmem_dev.base_addr+offset,
					buffer, len);
	if (bytes_written > 0) {
		return -EFAULT;
	}

//	printk(KERN_INFO "KVM_IVSHMEM: wrote %u bytes at offset %lu\n", (unsigned) len, offset);
	*poffset += len;
	return len;
}

static irqreturn_t kvm_ivshmem_interrupt (int irq, void *dev_instance)
{
	struct kvm_ivshmem_device * dev = dev_instance;
	u32 status;

	if (unlikely(dev == NULL))
		return IRQ_NONE;

	status = readl(dev->regs + IntrStatus);
	if (!status || (status == 0xFFFFFFFF))
		return IRQ_NONE;

	/* depending on the message we wake different structures */
	if (status == sema_irq) {
		up(&sema);
	} else if (status == wait_event_irq) {
		event_num = 1;
		wake_up_interruptible(&wait_queue);
	}

	printk(KERN_INFO "KVM_IVSHMEM: interrupt (status = 0x%04x)\n",
		   status);

	return IRQ_HANDLED;
}

__maybe_unused static int request_msix_vectors(struct kvm_ivshmem_device *ivs_info, int nvectors)
{
	int i, err;
	const char *name = "ivshmem";

	printk(KERN_INFO "devname is %s\n", name);
	ivs_info->nvectors = nvectors;


	ivs_info->msix_entries = kmalloc(nvectors * sizeof *ivs_info->msix_entries,
					   GFP_KERNEL);
	ivs_info->msix_names = kmalloc(nvectors * sizeof *ivs_info->msix_names,
					 GFP_KERNEL);

	for (i = 0; i < nvectors; ++i)
		ivs_info->msix_entries[i].entry = i;
		
	err = pci_enable_msix_range(ivs_info->dev, ivs_info->msix_entries, 0, ivs_info->nvectors);
	if (err > 0) {
		printk(KERN_INFO "no MSI. Back to INTx.\n");
		return -ENOSPC;
	}

	if (err) {
		printk(KERN_INFO "some error below zero %d\n", err);
		return err;
	}

	for (i = 0; i < nvectors; i++) {

		snprintf(ivs_info->msix_names[i], sizeof *ivs_info->msix_names,
		 "%s-config", name);

		err = request_irq(ivs_info->msix_entries[i].vector,
				  kvm_ivshmem_interrupt, 0,
				  ivs_info->msix_names[i], ivs_info);

		if (err) {
			printk(KERN_INFO "couldn't allocate irq for msi-x entry %d with vector %d\n", i, ivs_info->msix_entries[i].vector);
			return -ENOSPC;
		}
	}

	return 0;
}

static int kvm_ivshmem_probe_device (struct pci_dev *pdev,
					const struct pci_device_id * ent) {

	int result;

	printk("KVM_IVSHMEM: Probing for KVM_IVSHMEM Device\n");

	result = pci_enable_device(pdev);
	if (result) {
		printk(KERN_ERR "Cannot probe KVM_IVSHMEM device %s: error %d\n",
		pci_name(pdev), result);
		return result;
	}

	result = pci_request_regions(pdev, "kvm_ivshmem");
	if (result < 0) {
		printk(KERN_ERR "KVM_IVSHMEM: cannot request regions\n");
		goto pci_disable;
	} else printk(KERN_ERR "KVM_IVSHMEM: result is %d\n", result);

	kvm_ivshmem_dev.ioaddr = pci_resource_start(pdev, 2);
	kvm_ivshmem_dev.ioaddr_size = pci_resource_len(pdev, 2);

	kvm_ivshmem_dev.base_addr = pci_iomap(pdev, 2, 0);
	printk(KERN_INFO "KVM_IVSHMEM: iomap base = 0x%lx \n",
							(unsigned long) kvm_ivshmem_dev.base_addr);

	if (!kvm_ivshmem_dev.base_addr) {
		printk(KERN_ERR "KVM_IVSHMEM: cannot iomap region of size %lu\n",
							kvm_ivshmem_dev.ioaddr_size);
		goto pci_release;
	}

	printk(KERN_INFO "KVM_IVSHMEM: ioaddr = %x ioaddr_size = %lu\n",
						kvm_ivshmem_dev.ioaddr, kvm_ivshmem_dev.ioaddr_size);

	kvm_ivshmem_dev.regaddr =  pci_resource_start(pdev, 0);
	kvm_ivshmem_dev.reg_size = pci_resource_len(pdev, 0);
	kvm_ivshmem_dev.regs = pci_iomap(pdev, 0, 0x100);

	kvm_ivshmem_dev.dev = pdev;

	if (!kvm_ivshmem_dev.regs) {
		printk(KERN_ERR "KVM_IVSHMEM: cannot ioremap registers of size %d\n",
							kvm_ivshmem_dev.reg_size);
		goto reg_release;
	}

	/* set all masks to on */
	writel(0xffffffff, kvm_ivshmem_dev.regs + IntrMask);

	/* by default initialize semaphore to 0 */
	sema_init(&sema, 0);

	init_waitqueue_head(&wait_queue);
	event_num = 0;

	// if (request_msix_vectors(&kvm_ivshmem_dev, 4) != 0) {
	// 	printk(KERN_INFO "regular IRQs\n");
	// 	if (request_irq(pdev->irq, kvm_ivshmem_interrupt, IRQF_SHARED,
	// 						"kvm_ivshmem", &kvm_ivshmem_dev)) {
	// 		printk(KERN_ERR "KVM_IVSHMEM: cannot get interrupt %d\n", pdev->irq);
	// 		printk(KERN_INFO "KVM_IVSHMEM: irq = %u regaddr = %x reg_size = %d\n",
	// 				pdev->irq, kvm_ivshmem_dev.regaddr, kvm_ivshmem_dev.reg_size);
	// 	}
	// } else {
	// 	printk(KERN_INFO "MSI-X enabled\n");
	// }

	return 0;


reg_release:
	pci_iounmap(pdev, kvm_ivshmem_dev.base_addr);
pci_release:
	pci_release_regions(pdev);
pci_disable:
	pci_disable_device(pdev);
	return -EBUSY;

}

static void kvm_ivshmem_remove_device(struct pci_dev* pdev)
{

	printk(KERN_INFO "Unregister kvm_ivshmem device.\n");
	free_irq(pdev->irq,&kvm_ivshmem_dev);
	pci_iounmap(pdev, kvm_ivshmem_dev.regs);
	pci_iounmap(pdev, kvm_ivshmem_dev.base_addr);
	pci_release_regions(pdev);
	pci_disable_device(pdev);

}

static void __exit kvm_ivshmem_cleanup_module (void)
{
	pci_unregister_driver (&kvm_ivshmem_pci_driver);
	unregister_chrdev(device_major_nr, "kvm_ivshmem");
}


static int kvm_ivshmem_open(struct inode * inode, struct file * filp)
{

   printk(KERN_INFO "Opening kvm_ivshmem device\n");

   if (MINOR(inode->i_rdev) != KVM_IVSHMEM_DEVICE_MINOR_NUM) {
	  printk(KERN_INFO "minor number is %d\n", KVM_IVSHMEM_DEVICE_MINOR_NUM);
	  return -ENODEV;
   }

   return 0;
}

static int kvm_ivshmem_release(struct inode * inode, struct file * filp)
{

   return 0;
}

static int kvm_ivshmem_mmap(struct file *filp, struct vm_area_struct * vma)
{

	unsigned long len;
	unsigned long off;
	unsigned long start;

	// lock_kernel();


	off = vma->vm_pgoff << PAGE_SHIFT;
	start = kvm_ivshmem_dev.ioaddr;

	len=PAGE_ALIGN((start & ~PAGE_MASK) + kvm_ivshmem_dev.ioaddr_size);
	start &= PAGE_MASK;

	printk(KERN_INFO "%lu - %lu + %lu\n",vma->vm_end ,vma->vm_start, off);
	printk(KERN_INFO "%lu > %lu\n",(vma->vm_end - vma->vm_start + off), len);

	if ((vma->vm_end - vma->vm_start + off) > len) {
		// unlock_kernel();
		return -EINVAL;
	}

	off += start;
	vma->vm_pgoff = off >> PAGE_SHIFT;

	vma->vm_flags |= (VM_SHARED| VM_DONTEXPAND | VM_DONTDUMP);

	if(io_remap_pfn_range(vma, vma->vm_start,
		off >> PAGE_SHIFT, vma->vm_end - vma->vm_start,
		vma->vm_page_prot))
	{
		printk("mmap failed\n");
		// unlock_kernel();
		return -ENXIO;
	}
	// unlock_kernel();

	return 0;
}

static void test_mem(void)
{
	char data[5] = "12311";
	char data2[5];

	memcpy(kvm_ivshmem_dev.base_addr, data, 5);
	memcpy(data2, kvm_ivshmem_dev.base_addr, 5);

	printk(KERN_INFO "Data verified %s\n", data2);
}

rr_event_log_guest* rr_get_tail_event(void)
{
    rr_event_log_guest *event;
    rr_event_guest_queue_header *header;

    header = (rr_event_guest_queue_header *)kvm_ivshmem_dev.base_addr;

    if (header->current_pos == 0) {
        return NULL;
    }

    event = (rr_event_log_guest *)(kvm_ivshmem_dev.base_addr + header->header_size + \
                                   (header->current_pos - 1) * header->entry_size);

    return event;    
}


void *rr_alloc_new_event_entry(unsigned long size, int type)
{
    rr_event_guest_queue_header *header;
    rr_event_log_guest *entry;
	rr_event_entry_header *entry_header;
	unsigned long offset;
	unsigned long event_size = size + sizeof(rr_event_entry_header);

    header = (rr_event_guest_queue_header *)kvm_ivshmem_dev.base_addr;

    if (header->current_byte + event_size > header->total_size) {
        printk(KERN_ERR "RR queue is full, start over\n");
        header->current_byte = header->header_size;
    }

	offset = (unsigned long)kvm_ivshmem_dev.base_addr + header->current_byte;

	entry_header = (rr_event_entry_header *)offset;

	entry_header->type = type;

    entry = (void *)(offset + sizeof(rr_event_entry_header));

    header->current_pos++;
	header->current_byte += event_size;

    return entry;
}

void rr_append_to_queue(rr_event_log_guest *event_log)
{
    rr_event_guest_queue_header *header;

    header = (rr_event_guest_queue_header *)kvm_ivshmem_dev.base_addr;

    event_log->id = header->current_pos;

    memcpy(kvm_ivshmem_dev.base_addr + header->header_size + header->current_pos * header->entry_size,
           event_log, sizeof(rr_event_log_guest));

    header->current_pos++;

    return;
}

int rr_enabled(void)
{
    rr_event_guest_queue_header *header;
    header = (rr_event_guest_queue_header *)kvm_ivshmem_dev.base_addr;

    return header->rr_enabled;
}

static void rr_init_queue(void)
{
    rr_event_guest_queue_header header = {
        .header_size = PAGE_SIZE,
        .entry_size = 2 * PAGE_SIZE,
        .rr_enabled = 0,
    };
    rr_event_log_guest *event;
	unsigned long size;

    event = kmalloc(sizeof(rr_event_log_guest), GFP_KERNEL);
    event->type = 4;

	header.current_pos = 0;
	size = kvm_ivshmem_dev.ioaddr_size - header.header_size;
    header.total_pos = size / header.entry_size;
	header.total_size = size;

    printk(KERN_INFO "Initialized RR shared memory, "
          "total size=%lu header size=%d, current pos=%d, total_pos=%d\n", 
          size, header.header_size, header.current_pos, header.total_pos);

    memcpy(kvm_ivshmem_dev.base_addr, &header, sizeof(rr_event_guest_queue_header));

	// Warmup to touch shared memory
	while(rr_alloc_new_event_entry(header.entry_size, 0)!=NULL) {
		break;
	}

	header.current_byte = header.header_size;

	memcpy(kvm_ivshmem_dev.base_addr, &header, sizeof(rr_event_guest_queue_header));

    inited_queue = true;
    return;
}

bool rr_queue_inited(void)
{
    return inited_queue;
}

int __init kvm_ivshmem_init(void)
{

	int err = -ENOMEM;
    printk(KERN_INFO "Init ivshmem\n");

	/* Register device node ops. */
	err = register_chrdev(0, "kvm_ivshmem", &kvm_ivshmem_ops);
	if (err < 0) {
		printk(KERN_ERR "Unable to register kvm_ivshmem device\n");
		return err;
	}
	device_major_nr = err;
	printk("KVM_IVSHMEM: Major device number is: %d\n", device_major_nr);
	kvm_ivshmem_dev.enabled=FALSE;

	err = pci_register_driver(&kvm_ivshmem_pci_driver);
	if (err < 0) {
		goto error;
	}

    test_mem();

    rr_init_queue();

	return 0;

error:
	unregister_chrdev(device_major_nr, "kvm_ivshmem");
    // return;
	return err;
}
