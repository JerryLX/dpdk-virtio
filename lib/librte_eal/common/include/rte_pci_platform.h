#ifndef _RTE_PCI_PLATFORM_H_
#define _RTE_PCI_PLATFORM_H_

enum rte_kernel_driver {
    RTE_KDRV_UNKNOWN = 0,
    RTE_KDRV_IGB_UIO,
    RTE_KDRV_VFIO,
    RTE_KDRV_UIO_GENERIC,
    RTE_KDRV_NIC_UIO,
    RTE_KDRV_HNS_UIO,
    RTE_KDRV_PLF_UIO,
    RTE_KDRV_NONE,
};

#endif /* rte_pci_platform.h*/
