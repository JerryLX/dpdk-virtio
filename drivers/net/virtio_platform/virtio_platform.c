/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include <stdint.h>
#ifdef RTE_EXEC_ENV_LINUXAPP
 #include <dirent.h>
 #include <fcntl.h>
#endif

#include "virtio_platform.h"
#include "virtio_logs.h"
#include "virtqueue.h"

#undef PAGE_SIZE
#define PAGE_SIZE 4096

/*
 * Following macros are derived from linux/platform_regs.h, however,
 * we can't simply include that header here, as there is no such
 * file for non-Linux platform.
 */
#define PCI_CAPABILITY_LIST	0x34
#define PCI_CAP_ID_VNDR		0x09


static inline int
check_vq_phys_addr_ok(struct virtqueue *vq)
{
	/* Virtio PCI device VIRTIO_PCI_QUEUE_PF register is 32bit,
	 * and only accepts 32 bit page frame number.
	 * Check if the allocated physical memory exceeds 16TB.
	 */
	if ((vq->vq_ring_mem + vq->vq_ring_size - 1) >>
			(VIRTIO_PCI_QUEUE_ADDR_SHIFT + 32)) {
		PMD_INIT_LOG(ERR, "vring address shouldn't be above 16TB!");
		return 0;
	}

	return 1;
}

//====================================================
//IO Control Method
//Do not modify
//====================================================
static inline uint8_t
io_read8(char *addr)
{
	return *(volatile uint8_t *)addr;
}

static inline void
io_write8(uint8_t val, char *addr)
{
	*(volatile uint8_t *)addr = val;
}

static inline uint16_t
io_read16(char *addr)
{
	return *(volatile uint16_t *)addr;
}

static inline void
io_write16(uint16_t val, char *addr)
{
	*(volatile uint16_t *)addr = val;
}

static inline uint32_t
io_read32(char *addr)
{
	return *(volatile uint32_t *)addr;
}

static inline void
io_write32(uint32_t val, char *addr)
{
	*(volatile uint32_t *)addr = val;
}

static inline uint64_t
io_read64(char *addr)
{
	return *(volatile uint64_t *)addr;
}

static inline void
io_write64(uint64_t val, char *addr)
{
	*(volatile uint64_t *)addr = val;
}

/*
 * Since we are in legacy mode:
 * http://ozlabs.org/~rusty/virtio-spec/virtio-0.9.5.pdf
 *
 * "Note that this is possible because while the virtio header is PCI (i.e.
 * little) endian, the device-specific region is encoded in the native endian of
 * the guest (where such distinction is applicable)."
 *
 * For powerpc which supports both, qemu supposes that cpu is big endian and
 * enforces this for the virtio-net stuff.
 */
static void
vm_read_dev_config(struct virtio_hw *hw, size_t offset,
		       void *dst, int length)
{
	uint8_t *ptr = dst;
	int i;

	for(i = 0; i<length; i++)
		ptr[i] = io_read8(hw->base+VIRTIO_MMIO_CONFIG+offset+i);
}

static void
vm_write_dev_config(struct virtio_hw *hw, size_t offset,
			const void *src, int length)
{
	const uint8_t *ptr = src;
	int i;

	for(i = 0; i<length;i++)
		io_write8(ptr[i], hw->base+VIRTIO_MMIO_CONFIG+offset+i);

}


//To do:
//=======================================================
//Get value through MMIO
//You can refer to virtio_mmio.c
//=======================================================
static uint64_t
vm_get_features(struct virtio_hw *hw)
{
	io_write32(0, hw->base + VIRTIO_MMIO_HOST_FEATURES_SEL);
	return io_read32(hw->base + VIRTIO_MMIO_HOST_FEATURES);
}

static void
vm_set_features(struct virtio_hw *hw, uint64_t features)
{
	io_write32(0, hw->base + VIRTIO_MMIO_GUEST_FEATURES_SEL);
	io_write32(features & ((1ULL << 32) - 1), hw->base + VIRTIO_MMIO_GUEST_FEATURES);
	io_write32(1, hw->base + VIRTIO_MMIO_GUEST_FEATURES_SEL);
	io_write32(features >> 32, hw->base + VIRTIO_MMIO_GUEST_FEATURES);
}

static uint8_t
vm_get_status(struct virtio_hw *hw)
{
	return io_read32(hw->base + VIRTIO_MMIO_STATUS) & 0xff;
}

static void
vm_set_status(struct virtio_hw *hw, uint8_t status)
{
	if (status == 0) {
		PMD_DRV_LOG(ERR, "Status should never be set to 0!");
		return;
	}
	io_write32(status,(hw->base) + VIRTIO_MMIO_STATUS);
}

static void
vm_reset(struct virtio_hw *hw)
{
	io_write32(0, hw->base + VIRTIO_MMIO_STATUS);
}

static uint8_t
vm_get_isr(struct virtio_hw *hw)
{
	//maybe do not need this function
	(void) hw;
	return 0;
}

/* Enable one vector (0) for Link State Intrerrupt */
static uint16_t
vm_set_config_irq(struct virtio_hw *hw, uint16_t vec)
{
	(void)hw;
	(void)vec;	
	return 0;
}

static uint16_t
vm_get_queue_num(struct virtio_hw *hw, uint16_t queue_id)
{
	io_write32(queue_id, hw->base + VIRTIO_MMIO_QUEUE_SEL);
	return io_read32(hw->base + VIRTIO_MMIO_QUEUE_NUM_MAX);
}

static int
vm_setup_queue(struct virtio_hw *hw, struct virtqueue *vq)
{
	uint32_t src, num;
	if (!check_vq_phys_addr_ok(vq))
		return -1;
	io_write32(vq->vq_queue_index, hw->base + VIRTIO_MMIO_QUEUE_SEL);
//	if (io_read32(hw->base + VIRTIO_MMIO_QUEUE_PFN)) {
//		PMD_DRV_LOG(ERR, "Queue is already be set up!");
//		return -1;
//	}
	num = io_read32(hw->base + VIRTIO_MMIO_QUEUE_NUM_MAX);
	io_write32(num, hw->base + VIRTIO_MMIO_QUEUE_NUM);
	io_write32(PAGE_SIZE, hw->base + VIRTIO_MMIO_QUEUE_ALIGN);
	src = vq->vq_ring_mem >> PAGE_SHIFT;
	io_write32(src, hw->base + VIRTIO_MMIO_QUEUE_PFN);
	return 0;
}

static void
vm_del_queue(struct virtio_hw *hw, struct virtqueue *vq)
{
	io_write32(vq->vq_queue_index, hw->base + VIRTIO_MMIO_QUEUE_SEL);
	io_write32(0, hw->base + VIRTIO_MMIO_QUEUE_PFN);
}

static void
vm_notify_queue(struct virtio_hw *hw, struct virtqueue *vq)
{
	io_write32(vq->vq_queue_index, hw->base+ VIRTIO_MMIO_QUEUE_NOTIFY);
}


static int
vm_virtio_resource_init(struct rte_platform_device *platform_dev,
			    struct virtio_hw *hw, uint32_t *dev_flags)
{
	(void)platform_dev;
	(void)hw;
	(void)dev_flags;
	return 0;
}

static const struct virtio_platform_ops vm_ops = {
	.read_dev_cfg	= vm_read_dev_config,
	.write_dev_cfg	= vm_write_dev_config,
	.reset		= vm_reset,
	.get_status	= vm_get_status,
	.set_status	= vm_set_status,
	.get_features	= vm_get_features,
	.set_features	= vm_set_features,
	.get_isr	= vm_get_isr,
	.set_config_irq	= vm_set_config_irq,
	.get_queue_num	= vm_get_queue_num,
	.setup_queue	= vm_setup_queue,
	.del_queue	= vm_del_queue,
	.notify_queue	= vm_notify_queue,
};


void
vtplatform_read_dev_config(struct virtio_hw *hw, size_t offset,
		      void *dst, int length)
{
	hw->vtplatform_ops->read_dev_cfg(hw, offset, dst, length);
}

void
vtplatform_write_dev_config(struct virtio_hw *hw, size_t offset,
		       const void *src, int length)
{
	hw->vtplatform_ops->write_dev_cfg(hw, offset, src, length);
}

uint64_t
vtplatform_negotiate_features(struct virtio_hw *hw, uint64_t host_features)
{
	uint64_t features;

	/*
	 * Limit negotiated features to what the driver, virtqueue, and
	 * host all support.
	 */
	features = host_features & hw->guest_features;
	hw->vtplatform_ops->set_features(hw, features);

	return features;
}

void
vtplatform_reset(struct virtio_hw *hw)
{
	hw->vtplatform_ops->set_status(hw, VIRTIO_CONFIG_STATUS_RESET);
}

void
vtplatform_reinit_complete(struct virtio_hw *hw)
{
	vtplatform_set_status(hw, VIRTIO_CONFIG_STATUS_DRIVER_OK);
}

void
vtplatform_set_status(struct virtio_hw *hw, uint8_t status)
{
	if (status != VIRTIO_CONFIG_STATUS_RESET)
		status |= hw->vtplatform_ops->get_status(hw);
	hw->vtplatform_ops->set_status(hw, status);
}

uint8_t
vtplatform_get_status(struct virtio_hw *hw)
{
	return hw->vtplatform_ops->get_status(hw);
}

uint8_t
vtplatform_isr(struct virtio_hw *hw)
{
	return hw->vtplatform_ops->get_isr(hw);
}


/* Enable one vector (0) for Link State Intrerrupt */
uint16_t
vtplatform_irq_config(struct virtio_hw *hw, uint16_t vec)
{
	return hw->vtplatform_ops->set_config_irq(hw, vec);
}

// static void *
// get_cfg_addr(struct rte_platform_device *dev, struct virtio_platform_cap *cap)
// {
// 	uint8_t  bar    = cap->bar;
// 	uint32_t length = cap->length;
// 	uint32_t offset = cap->offset;
// 	uint8_t *base;

// 	if (bar > 5) {
// 		PMD_INIT_LOG(ERR, "invalid bar: %u", bar);
// 		return NULL;
// 	}

// 	if (offset + length < offset) {
// 		PMD_INIT_LOG(ERR, "offset(%u) + length(%u) overflows",
// 			offset, length);
// 		return NULL;
// 	}

// 	if (offset + length > dev->mem_resource[bar].len) {
// 		PMD_INIT_LOG(ERR,
// 			"invalid cap: overflows bar space: %u > %" PRIu64,
// 			offset + length, dev->mem_resource[bar].len);
// 		return NULL;
// 	}

// 	base = dev->mem_resource[bar].addr;
// 	if (base == NULL) {
// 		PMD_INIT_LOG(ERR, "bar %u base addr is NULL", bar);
// 		return NULL;
// 	}

// 	return base + offset;
// }

// static int
// virtio_read_caps(struct rte_platform_device *dev, struct virtio_hw *hw)
// {
// 	uint8_t pos;
// 	struct virtio_platform_cap cap;
// 	int ret;

// 	if (rte_eal_platform_map_device(dev)) {
// 		PMD_INIT_LOG(DEBUG, "failed to map platform device!");
// 		return -1;
// 	}

// 	ret = rte_eal_platform_read_config(dev, &pos, 1, PCI_CAPABILITY_LIST);
// 	if (ret < 0) {
// 		PMD_INIT_LOG(DEBUG, "failed to read platform capability list");
// 		return -1;
// 	}

// 	while (pos) {
// 		ret = rte_eal_platform_read_config(dev, &cap, sizeof(cap), pos);
// 		if (ret < 0) {
// 			PMD_INIT_LOG(ERR,
// 				"failed to read platform cap at pos: %x", pos);
// 			break;
// 		}

// 		if (cap.cap_vndr != PCI_CAP_ID_VNDR) {
// 			PMD_INIT_LOG(DEBUG,
// 				"[%2x] skipping non VNDR cap id: %02x",
// 				pos, cap.cap_vndr);
// 			goto next;
// 		}

// 		PMD_INIT_LOG(DEBUG,
// 			"[%2x] cfg type: %u, bar: %u, offset: %04x, len: %u",
// 			pos, cap.cfg_type, cap.bar, cap.offset, cap.length);

// 		switch (cap.cfg_type) {
// 		case VIRTIO_PCI_CAP_COMMON_CFG:
// 			hw->common_cfg = get_cfg_addr(dev, &cap);
// 			break;
// 		case VIRTIO_PCI_CAP_NOTIFY_CFG:
// 			rte_eal_platform_read_config(dev, &hw->notify_off_multiplier,
// 						4, pos + sizeof(cap));
// 			hw->notify_base = get_cfg_addr(dev, &cap);
// 			break;
// 		case VIRTIO_PCI_CAP_DEVICE_CFG:
// 			hw->dev_cfg = get_cfg_addr(dev, &cap);
// 			break;
// 		case VIRTIO_PCI_CAP_ISR_CFG:
// 			hw->isr = get_cfg_addr(dev, &cap);
// 			break;
// 		}

// next:
// 		pos = cap.cap_next;
// 	}

// 	if (hw->common_cfg == NULL || hw->notify_base == NULL ||
// 	    hw->dev_cfg == NULL    || hw->isr == NULL) {
// 		PMD_INIT_LOG(INFO, "no modern virtio platform device found.");
// 		return -1;
// 	}

// 	PMD_INIT_LOG(INFO, "found modern virtio platform device.");

// 	PMD_INIT_LOG(DEBUG, "common cfg mapped at: %p", hw->common_cfg);
// 	PMD_INIT_LOG(DEBUG, "device cfg mapped at: %p", hw->dev_cfg);
// 	PMD_INIT_LOG(DEBUG, "isr cfg mapped at: %p", hw->isr);
// 	PMD_INIT_LOG(DEBUG, "notify base: %p, notify off multiplier: %u",
// 		hw->notify_base, hw->notify_off_multiplier);

// 	return 0;
// }

/*
 * Return -1:
 *   if there is error mapping with VFIO/UIO.
 * Return 0 on success.
 * Init platform device
 */
int
vtplatform_init(struct rte_platform_device *dev, struct virtio_hw *hw,
	   uint32_t *dev_flags)
{
	int version;
	hw->dev = dev;
	hw->vtplatform_ops = &vm_ops;
	version = io_read32(hw->base + VIRTIO_MMIO_VERSION);
	printf("version:%d!!!!!!!!!!!!!!!!!!!!!!!!!!\n",version);
	io_write32(PAGE_SIZE, hw->base + VIRTIO_MMIO_GUEST_PAGE_SIZE);
	(void)dev_flags;
	(void)vm_virtio_resource_init;
	// if (vm_virtio_resource_init(dev, hw, dev_flags) < 0) {
	// 	return -1;
	// }
	return 0;
}
