#ifndef _RTE_ETHDEV_PLATFORM_H_
#define _RTE_ETHDEV_PLATFORM_H_

#include <rte_malloc.h>
#include <rte_platform.h>
#include <rte_ethdev.h>

/**
 * Copy platform device info to the Ethernet device data.
 *
 * @param eth_dev
 * The *eth_dev* pointer is the address of the *rte_eth_dev* structure.
 * @param platform_dev
 * The *platform_dev* pointer is the address of the *rte_platform_device* structure.
 *
 * @return
 *   - 0 on success, negative on error
 */

static inline void
rte_eth_copy_platform_info(struct rte_eth_dev *eth_dev, struct rte_platform_device *platform_dev)
{
	if ((eth_dev == NULL) || (platform_dev == NULL)) {
		RTE_PMD_DEBUG_TRACE("NULL pointer eth_dev=%p platform_dev=%p\n",
				eth_dev, platform_dev);
		return;
	}

	eth_dev->data->dev_flags = 0;
	if (platform_dev->driver->drv_flags & RTE_PCI_DRV_INTR_LSC)
		eth_dev->data->dev_flags |= RTE_ETH_DEV_INTR_LSC;
	// if (platform_dev->driver->drv_flags & RTE_PCI_DRV_DETACHABLE)    temporarily removed for debug by mqc
	//	  eth_dev->data->dev_flags |= RTE_ETH_DEV_DETACHABLE;

	eth_dev->data->kdrv = platform_dev->kdrv;
	eth_dev->data->numa_node = platform_dev->numa_node;
	eth_dev->data->drv_name = platform_dev->driver->name;
}
/**
 * @internal
 * Allocates a new ethdev slot for an ethernet device and returns the pointer
 * to that slot for the driver to use.
 *
 * @param dev
 *	Pointer to the PLATFORM device
 *
 * @param private_data_size
 *	Size of private data structure
 *
 * @return
 *	A pointer to a rte_eth_dev or NULL if allocation failed.
 */
static inline struct rte_eth_dev *
rte_eth_dev_platform_allocate(struct rte_platform_device *dev, size_t private_data_size)
{
	struct rte_eth_dev *eth_dev;
	const char *name;

	if (!dev)
		return NULL;

	name = dev->name;
	if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
		eth_dev = rte_eth_dev_allocate(name);
		if (!eth_dev)
			return NULL;

		if (private_data_size) {
			eth_dev->data->dev_private = rte_zmalloc_socket(name,
				private_data_size, RTE_CACHE_LINE_SIZE,
				dev->device.numa_node);
			if (!eth_dev->data->dev_private) {
				rte_eth_dev_release_port(eth_dev);
				return NULL;
			}
		}
	} else {
		eth_dev = rte_eth_dev_attach_secondary(name);
		if (!eth_dev)
			return NULL;
	}

	eth_dev->device = &dev->device;
	eth_dev->intr_handle = &dev->intr_handle;
	rte_eth_copy_platform_info(eth_dev, dev);
	return eth_dev;
}

static inline void
rte_eth_dev_platform_release(struct rte_eth_dev *eth_dev)
{
	/* free ether device */
	rte_eth_dev_release_port(eth_dev);

	if (rte_eal_process_type() == RTE_PROC_PRIMARY)
		rte_free(eth_dev->data->dev_private);

	eth_dev->data->dev_private = NULL;

	/*
	 * Secondary process will check the name to attach.
	 * Clear this field to avoid attaching a released ports.
	 */
	eth_dev->data->name[0] = '\0';

	eth_dev->device = NULL;
	eth_dev->intr_handle = NULL;
}

typedef int (*eth_dev_platform_callback_t)(struct rte_eth_dev *eth_dev);

/**
 * @internal
 * Wrapper for use by platform drivers in a .probe function to attach to a ethdev
 * interface.
 */
static inline int
rte_eth_dev_platform_generic_probe(struct rte_platform_device *platform_dev,
	size_t private_data_size, eth_dev_platform_callback_t dev_init)
{
	struct rte_eth_dev *eth_dev;
	int ret;

	printf("rte_eth_dev_platform_generic_probe:%s\n",platform_dev->name); // for debug by mqc
	
	eth_dev = rte_eth_dev_platform_allocate(platform_dev, private_data_size);
	if (!eth_dev)
		return -ENOMEM;

	RTE_FUNC_PTR_OR_ERR_RET(*dev_init, -EINVAL);
	ret = dev_init(eth_dev);
	if (ret)
		rte_eth_dev_platform_release(eth_dev);

	return ret;
}

/**
 * @internal
 * Wrapper for use by platform drivers in a .remove function to detach a ethdev
 * interface.
 */
static inline int
rte_eth_dev_platform_generic_remove(struct rte_platform_device *platform_dev,
	eth_dev_platform_callback_t dev_uninit)
{
	struct rte_eth_dev *eth_dev;
	int ret;

	eth_dev = rte_eth_dev_allocated(platform_dev->device.name);
	if (!eth_dev)
		return -ENODEV;

	if (dev_uninit) {
		ret = dev_uninit(eth_dev);
		if (ret)
			return ret;
	}

	rte_eth_dev_platform_release(eth_dev);
	return 0;
}

#endif /* _RTE_ETHDEV_PLATFORM_H_ */
