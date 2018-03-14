
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/device.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/uio_driver.h>
#include <linux/io.h>
#include <linux/version.h>
#include <linux/slab.h>
#include <linux/acpi.h>
#include <linux/string.h>
#include <linux/clk.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/phy.h>
#include <linux/iommu.h>
#include "hnae.h"
#include "hns_uio.h"
#include "compat.h"
//#include "hns_dsaf_reg.h"
//#include "hns_dsaf_main.h"
//#include "hns_dsaf_rcb.h"

#ifndef UIO_OK
#define UIO_OK 0
#endif

#ifndef UIO_ERROR
#define UIO_ERROR -1
#endif

#ifndef PRINT
#define PRINT(LOGLEVEL, fmt, ...) printk(LOGLEVEL "[Func: %s. Line: %d] " fmt, \
					 __func__, __LINE__, ## __VA_ARGS__)
#endif

#define MODE_IDX_IN_NAME 8
#define HNS_UIO_DEV_MAX 129


struct hns_uio_ioctrl_para {
    unsigned long long index;
    unsigned long long cmd;
    unsigned long long value;
    unsigned char data[200];
};

static int char_dev_flag;
static int uio_index;
struct rte_uio_platform_dev *uio_dev_info[HNS_UIO_DEV_MAX] = {
    0
};

struct char_device char_dev;
struct tast_struct *ring_task;
unsigned int kthread_stop_flag;

static int port_vf[] = {
    0, 0, 0, 8, 16, 32, 128, 0, 0, 0, 8, 16, 64, 1, 2, 4, 16, 0
};

#define HNS_PHY_PAGE_MDIX   0
#define HNS_PHY_PAGE_LED    3
#define HNS_PHY_PAGE_COPPER 0

#define HNS_PHY_PAGE_REG 22             /* Page Selection Reg. */
#define HNS_PHY_CSC_REG	 16             /* Copper Specific Control Register */
#define HNS_PHY_CSS_REG	 17             /* Copper Specific Status Register */
#define HNS_LED_FC_REG	 16             /* LED Function Control Reg. */
#define HNS_LED_PC_REG	 17             /* LED Polarity Control Reg. */

#define HNS_LED_FORCE_ON  9
#define HNS_LED_FORCE_OFF 8

#define HNS_CHIP_VERSION  660
#define HNS_NET_STATS_CNT 26

#define PHY_MDIX_CTRL_S	(5)
#define PHY_MDIX_CTRL_M	(3 << PHY_MDIX_CTRL_S)

#define PHY_MDIX_STATUS_B	(6)
#define PHY_SPEED_DUP_RESOLVE_B	(11)
#define SOC_NET			(1)


static const char hns_nic_test_strs[][ETH_GSTRING_LEN] = {
	"Mac    Loopback test",
	"Serdes Loopback test",
	"Phy    Loopback test"
};

int hns_uio_get_queue_mode(enum dsaf_mode dsaf_mode)
{
    switch(dsaf_mode){
        case DSAF_MODE_DISABLE_6PORT_0VM:
        case DSAF_MODE_DISABLE_FIX:
        case DSAF_MODE_DISABLE_SP:
            return 1;
        case DSAF_MODE_DISABLE_2PORT_64VM:
            return 64;
        case DSAF_MODE_DISABLE_6PORT_16VM:
        case DSAF_MODE_DISABLE_2PORT_16VM:
            return 16;
        default:
            return 1;
    }
    return 1;
}

/**
 * hns_nic_get_drvinfo - get net driver info
 * @dev: net device
 * @drvinfo: driver info
 */
static void hns_nic_get_drvinfo(struct net_device      *net_dev,
				struct ethtool_drvinfo *drvinfo)
{
	struct rte_uio_platform_dev *priv = netdev_priv(net_dev);

	assert(priv);

	strncpy(drvinfo->version, HNAE_DRIVER_VERSION,
		sizeof(drvinfo->version));
	drvinfo->version[sizeof(drvinfo->version) - 1] = '\0';

	strncpy(drvinfo->driver, DRIVER_UIO_NAME, sizeof(drvinfo->driver));
	drvinfo->driver[sizeof(drvinfo->driver) - 1] = '\0';

	strncpy(drvinfo->bus_info, priv->dev->bus->name,
		sizeof(drvinfo->bus_info));
	drvinfo->bus_info[ETHTOOL_BUSINFO_LEN - 1] = '\0';

	strncpy(drvinfo->fw_version, "N/A", ETHTOOL_FWVERS_LEN);
	drvinfo->eedump_len = 0;
	drvinfo->reserved2[0] = SOC_NET;
}

/**
 * get_ethtool_stats - get detail statistics.
 * @dev: net device
 * @stats: statistics info.
 * @data: statistics data.
 */
void hns_get_ethtool_stats(struct net_device *netdev,
			   struct ethtool_stats *stats, u64 *data)
{
	u64 *p = data;
	struct rte_uio_platform_dev *priv = netdev_priv(netdev);
	struct hnae_handle *h = priv->ae_handle;
	const struct rtnl_link_stats64 *net_stats;
	struct rtnl_link_stats64 temp;

	if (!h->dev->ops->get_stats || !h->dev->ops->update_stats) {
		netdev_err(netdev, "get_stats or update_stats is null!\n");
		return;
	}

	h->dev->ops->update_stats(h, &netdev->stats);

	net_stats = dev_get_stats(netdev, &temp);

	/* get netdev statistics */
	p[0] = net_stats->rx_packets;
	p[1] = net_stats->tx_packets;
	p[2] = net_stats->rx_bytes;
	p[3] = net_stats->tx_bytes;
	p[4] = net_stats->rx_errors;
	p[5] = net_stats->tx_errors;
	p[6] = net_stats->rx_dropped;
	p[7] = net_stats->tx_dropped;
	p[8] = net_stats->multicast;
	p[9] = net_stats->collisions;
	p[10] = net_stats->rx_over_errors;
	p[11] = net_stats->rx_crc_errors;
	p[12] = net_stats->rx_frame_errors;
	p[13] = net_stats->rx_fifo_errors;
	p[14] = net_stats->rx_missed_errors;
	p[15] = net_stats->tx_aborted_errors;
	p[16] = net_stats->tx_carrier_errors;
	p[17] = net_stats->tx_fifo_errors;
	p[18] = net_stats->tx_heartbeat_errors;
	p[19] = net_stats->rx_length_errors;
	p[20] = net_stats->tx_window_errors;
	p[21] = net_stats->rx_compressed;
	p[22] = net_stats->tx_compressed;

	p[23] = netdev->rx_dropped.counter;
	p[24] = netdev->tx_dropped.counter;

	/* get driver statistics */
	h->dev->ops->get_stats(h, &p[26]);
}

/**
 * get_strings: Return a set of strings that describe the requested objects
 * @dev: net device
 * @stats: string set ID.
 * @data: objects data.
 */
void hns_get_strings(struct net_device *netdev, u32 stringset, u8 *data)
{	struct rte_uio_platform_dev *priv = netdev_priv(netdev);
	struct hnae_handle *h = priv->ae_handle;
	char *buff = (char *)data;

	if (!h->dev->ops->get_strings) {
		netdev_err(netdev, "h->dev->ops->get_strings is null!\n");
		return;
	}

		snprintf(buff, ETH_GSTRING_LEN, "rx_packets");
		buff = buff + ETH_GSTRING_LEN;
		snprintf(buff, ETH_GSTRING_LEN, "tx_packets");
		buff = buff + ETH_GSTRING_LEN;
		snprintf(buff, ETH_GSTRING_LEN, "rx_bytes");
		buff = buff + ETH_GSTRING_LEN;
		snprintf(buff, ETH_GSTRING_LEN, "tx_bytes");
		buff = buff + ETH_GSTRING_LEN;
		snprintf(buff, ETH_GSTRING_LEN, "rx_errors");
		buff = buff + ETH_GSTRING_LEN;
		snprintf(buff, ETH_GSTRING_LEN, "tx_errors");
		buff = buff + ETH_GSTRING_LEN;
		snprintf(buff, ETH_GSTRING_LEN, "rx_dropped");
		buff = buff + ETH_GSTRING_LEN;
		snprintf(buff, ETH_GSTRING_LEN, "tx_dropped");
		buff = buff + ETH_GSTRING_LEN;
		snprintf(buff, ETH_GSTRING_LEN, "multicast");
		buff = buff + ETH_GSTRING_LEN;
		snprintf(buff, ETH_GSTRING_LEN, "collisions");
		buff = buff + ETH_GSTRING_LEN;
		snprintf(buff, ETH_GSTRING_LEN, "rx_over_errors");
		buff = buff + ETH_GSTRING_LEN;
		snprintf(buff, ETH_GSTRING_LEN, "rx_crc_errors");
		buff = buff + ETH_GSTRING_LEN;
		snprintf(buff, ETH_GSTRING_LEN, "rx_frame_errors");
		buff = buff + ETH_GSTRING_LEN;
		snprintf(buff, ETH_GSTRING_LEN, "rx_fifo_errors");
		buff = buff + ETH_GSTRING_LEN;
		snprintf(buff, ETH_GSTRING_LEN, "rx_missed_errors");
		buff = buff + ETH_GSTRING_LEN;
		snprintf(buff, ETH_GSTRING_LEN, "tx_aborted_errors");
		buff = buff + ETH_GSTRING_LEN;
		snprintf(buff, ETH_GSTRING_LEN, "tx_carrier_errors");
		buff = buff + ETH_GSTRING_LEN;
		snprintf(buff, ETH_GSTRING_LEN, "tx_fifo_errors");
		buff = buff + ETH_GSTRING_LEN;
		snprintf(buff, ETH_GSTRING_LEN, "tx_heartbeat_errors");
		buff = buff + ETH_GSTRING_LEN;
		snprintf(buff, ETH_GSTRING_LEN, "rx_length_errors");
		buff = buff + ETH_GSTRING_LEN;
		snprintf(buff, ETH_GSTRING_LEN, "tx_window_errors");
		buff = buff + ETH_GSTRING_LEN;
		snprintf(buff, ETH_GSTRING_LEN, "rx_compressed");
		buff = buff + ETH_GSTRING_LEN;
		snprintf(buff, ETH_GSTRING_LEN, "tx_compressed");
		buff = buff + ETH_GSTRING_LEN;
		snprintf(buff, ETH_GSTRING_LEN, "netdev_rx_dropped");
		buff = buff + ETH_GSTRING_LEN;
		snprintf(buff, ETH_GSTRING_LEN, "netdev_tx_dropped");
		buff = buff + ETH_GSTRING_LEN;

		snprintf(buff, ETH_GSTRING_LEN, "netdev_tx_timeout");
		buff = buff + ETH_GSTRING_LEN;

		h->dev->ops->get_strings(h, stringset, (u8 *)buff);
}

/**
 * nic_get_sset_count - get string set count witch returned by
   nic_get_strings.
 * @dev: net device
 * @stringset: string set index, 0: self test string; 1: statistics string.
 *
 * Return string set count.
 */
int hns_get_sset_count(struct net_device *netdev, int stringset)
{
	struct rte_uio_platform_dev *priv = netdev_priv(netdev);
	struct hnae_handle *h = priv->ae_handle;
	struct hnae_ae_ops *ops = h->dev->ops;

	if (!ops->get_sset_count) {
		netdev_err(netdev, "get_sset_count is null!\n");
		return -EOPNOTSUPP;
	}
	if (stringset == ETH_SS_TEST) {
		u32 cnt = (sizeof(hns_nic_test_strs) / ETH_GSTRING_LEN);

		if (priv->ae_handle->phy_if == PHY_INTERFACE_MODE_XGMII)
			cnt--;

		if ((!netdev->phydev) || (netdev->phydev->is_c45))
			cnt--;

		return cnt;
	} else {
		return (HNS_NET_STATS_CNT + ops->get_sset_count(h, stringset));
	}
}

static struct ethtool_ops hns_ethtool_ops = {
	.get_drvinfo	   = hns_nic_get_drvinfo,
	.get_link	   = NULL, /* hns_nic_get_link, */
	.get_settings	= NULL,    /* hns_nic_get_settings, */
	.set_settings	= NULL,    /* hns_nic_set_settings, */
	.get_ringparam	= NULL,    /* hns_get_ringparam, */
	.get_pauseparam = NULL,    /* hns_get_pauseparam, */
	.set_pauseparam = NULL,    /* hns_set_pauseparam, */
	.get_coalesce	= NULL,    /* hns_get_coalesce, */
	.set_coalesce	= NULL,    /* hns_set_coalesce, */
	.get_channels	= NULL,    /* hns_get_channels, */
	.self_test	   = NULL, /* hns_nic_self_test, */
	.get_strings	   = hns_get_strings,
	.get_sset_count	   = hns_get_sset_count,
	.get_ethtool_stats = hns_get_ethtool_stats,
	.set_phys_id  = NULL,      /* hns_set_phys_id, */
	.get_regs_len = NULL,      /* hns_get_regs_len, */
	.get_regs	   = NULL, /* hns_get_regs, */
	.nway_reset	   = NULL, /* hns_nic_nway_reset, */
};

void hns_ethtool_set_ops(struct net_device *netdev)
{
	netdev->ethtool_ops = &hns_ethtool_ops;
}

static int netdev_open(struct net_device *netdev){
	struct rte_uio_platform_dev *priv = netdev_priv(netdev);
	struct hnae_handle *h = priv->ae_handle;
	int ret;

	priv->link = 0;
	netif_carrier_off(netdev);

	ret = netif_set_real_num_tx_queues(netdev, h->q_num);
	if (ret < 0) {
		netdev_err(netdev, "netif_set_real_num_tx_queues fail, ret=%d!\n",
			   ret);
		return ret;
	}

	ret = netif_set_real_num_rx_queues(netdev, h->q_num);
	if (ret < 0) {
		netdev_err(netdev,
			   "netif_set_real_num_rx_queues fail, ret=%d!\n", ret);
		return ret;
	}

	//ret = hns_nic_net_up(netdev);
	if (ret) {
		netdev_err(netdev,
			   "hns net up fail, ret=%d!\n", ret);
		return ret;
	}

	return 0;
}

static struct net_device_stats *netdev_stats(struct net_device *netdev)
{
    struct rte_uio_platform_dev *adapter;
    int ifdx;

    adapter = netdev_priv(netdev);
    ifdx = adapter->bd_number;

    adapter->nstats.rx_packets = 0;
    adapter->nstats.tx_packets = 0;
    adapter->nstats.rx_bytes = 0;
    adapter->nstats.tx_bytes = 0;

    return &adapter->nstats;
}

static int netdev_set_features(struct net_device *netdev,
                            netdev_features_t features)
{
    (void)netdev;
    (void)features;
    return 0;
}

static netdev_features_t netdev_fix_features(struct net_device *netdev,
                                        netdev_features_t features)
{
    (void)netdev;
    (void)features;
    return 0;
}

static void netdev_no_ret(struct net_device *netdev)
{
    (void)netdev;
}

static int netdev_xmit(struct sk_buff *skb, struct net_device *netdev)
{
    (void)netdev;
    (void)skb;
    return 0;
}

/* A native net_device_ops struct to get the interface visible to the OS */
static const struct net_device_ops netdev_ops = {
    .ndo_open = netdev_open,
    .ndo_stop = netdev_open, 
    .ndo_start_xmit = netdev_xmit,
    .ndo_set_rx_mode = netdev_no_ret,
    .ndo_validate_addr = netdev_open,
    .ndo_set_mac_address = NULL,
    .ndo_change_mtu = NULL,
    .ndo_tx_timeout = netdev_no_ret,
    .ndo_vlan_rx_add_vid = NULL,
    .ndo_vlan_rx_kill_vid = NULL,
    .ndo_do_ioctl = NULL,
    .ndo_set_vf_mac = NULL,
    .ndo_set_vf_vlan = NULL,
    .ndo_set_vf_rate = NULL,
    .ndo_set_vf_spoofchk = NULL,
    .ndo_get_vf_config = NULL,
    .ndo_get_stats = netdev_stats,
    .ndo_setup_tc = NULL,

    .ndo_set_features = netdev_set_features,
    .ndo_fix_features = netdev_fix_features,
    .ndo_fdb_add = NULL,
};

void netdev_assign_netdev_ops(struct net_device *dev){
    dev->netdev_ops = &netdev_ops;
}

static ssize_t hns_cdev_read(struct file *file,
        char __user *buffer, size_t length, loff_t *offset)
{
    return UIO_OK;
}

static ssize_t hns_cdev_write(struct file *file,
        const char __user *buffer, size_t length, loff_t *offset)
{
    return UIO_OK;
}

static int hns_uio_change_mtu(struct rte_uio_platform_dev *priv, int new_mtu)
{
	struct net_device *netdev = priv->netdev;
	struct hnae_handle *h = priv->ae_handle;
	//bool if_running = netif_running(netdev);
	int ret;

	/* MTU < 68 is an error and causes problems on some kernels */
	if (new_mtu < 68)
		return -EINVAL;

	/* MTU no change */
	if (new_mtu == netdev->mtu)
		return 0;

	if (!h->dev->ops->set_mtu)
		return -ENOTSUPP;

//	if (if_running) {
//		(void)hns_nic_net_stop(netdev);
//		msleep(100);
//	}

//	if (priv->enet_ver != AE_VERSION_1 &&
//	    netdev->mtu <= BD_SIZE_2048_MAX_MTU &&
//	    new_mtu > BD_SIZE_2048_MAX_MTU) {
		/* update desc */
//		hnae_reinit_all_ring_desc(h);

		/* clear the package which the chip has fetched */
//		ret = hns_nic_clear_all_rx_fetch(netdev);

		/* the page offset must be consist with desc */
//		hnae_reinit_all_ring_page_off(h);

//		if (ret) {
//			netdev_err(netdev, "clear the fetched desc fail\n");
//			goto out;
//		}
//	}

	ret = h->dev->ops->set_mtu(h, new_mtu);
	if (ret) {
		netdev_err(netdev, "set mtu fail, return value %d\n",
			   ret);
		goto out;
	}

	/* finally, set new mtu to netdevice */
	netdev->mtu = new_mtu;

out:
//	if (if_running) {
//		if (hns_nic_net_open(netdev)) {
			netdev_err(netdev, "hns net open fail\n");
			ret = -EINVAL;
//		}
//	}

	return ret;
}

void hns_uio_get_stats(struct rte_uio_platform_dev *priv,
                       unsigned long long    *data)
{
    unsigned long long *p = data;
    struct hnae_handle *h = priv->ae_handle;
    const struct rtnl_link_stats64 *net_stats;
    struct rtnl_link_stats64 temp;

    if (!h->dev->ops->get_stats || !h->dev->ops->update_stats) {
        netdev_err(priv->netdev,                            
                "get_stats or update_stats is null!\n");
        return;
    }

    h->dev->ops->update_stats(h, &priv->netdev->stats);

    net_stats = dev_get_stats(priv->netdev, &temp);

    /* get netdev statistics */
    p[0]  = net_stats->rx_packets;
    p[1]  = net_stats->tx_packets;
    p[2]  = net_stats->rx_bytes;
    p[3]  = net_stats->tx_bytes;
    p[4]  = net_stats->rx_errors;
    p[5]  = net_stats->tx_errors;
    p[6]  = net_stats->rx_dropped;
    p[7]  = net_stats->tx_dropped;
    p[8]  = net_stats->multicast;
    p[9]  = net_stats->collisions;
    p[10] = net_stats->rx_over_errors;
    p[11] = net_stats->rx_crc_errors;
    p[12] = net_stats->rx_frame_errors;
    p[13] = net_stats->rx_fifo_errors;
    p[14] = net_stats->rx_missed_errors;
    p[15] = net_stats->tx_aborted_errors;
    p[16] = net_stats->tx_carrier_errors;
    p[17] = net_stats->tx_fifo_errors;
    p[18] = net_stats->tx_heartbeat_errors;
    p[19] = net_stats->rx_length_errors;
    p[20] = net_stats->tx_window_errors;
    p[21] = net_stats->rx_compressed;
    p[22] = net_stats->tx_compressed;

    p[23] = priv->netdev->rx_dropped.counter;
    p[24] = priv->netdev->tx_dropped.counter;

    /* get driver statistics */
    h->dev->ops->get_stats(h, &p[25]);
}

void hns_uio_pausefrm_cfg(void *mac_drv, u32 rx_en, u32 tx_en)
{
	struct hns_mac_cb *mac_cb = (struct hns_mac_cb *)mac_drv;
	u8 __iomem *base = (u8 *)mac_cb->vaddr + XGMAC_MAC_PAUSE_CTRL_REG;
	u32 origin = readl(base);

	dsaf_set_bit(origin, XGMAC_PAUSE_CTL_TX_B, !!tx_en);
	dsaf_set_bit(origin, XGMAC_PAUSE_CTL_RX_B, !!rx_en);
	writel(origin, base);
}

void hns_uio_set_iommu(struct rte_uio_platform_dev *priv, unsigned long iova,
		       unsigned long paddr, int gfp_order)
{
	struct iommu_domain *domain;
	int ret = 0;

	domain = iommu_domain_alloc(priv->dev->bus);

	if (!domain)
		PRINT(KERN_ERR, "domain is null\n");

	ret = iommu_attach_device(domain, priv->dev);
	PRINT(KERN_ERR, "domain is null = %d\n", ret);

	ret =
		iommu_map(domain, iova, (phys_addr_t)paddr, gfp_order,
			  (IOMMU_WRITE | IOMMU_READ | IOMMU_CACHE));
	PRINT(KERN_ERR, "domain is null = %d\n", ret);
}

long hns_cdev_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int ret = 0;
	int index = 0;
	void __user *parg;
	struct hns_uio_ioctrl_para uio_para;
	struct rte_uio_platform_dev *priv = NULL;
	struct hnae_handle *handle;

	/* unsigned long long data[128] = {0}; */

	parg = (void __user *)arg;

	if (copy_from_user(&uio_para, parg,
			   sizeof(struct hns_uio_ioctrl_para))) {
		PRINT(KERN_ERR, "copy_from_user error.\n");
		return UIO_ERROR;
	}

	if (uio_para.index >= uio_index) {
		PRINT(KERN_ERR, "Device index is out of range (%d).\n",
		      uio_index);
		return UIO_ERROR;
	}

	priv = uio_dev_info[uio_para.index];
	if (!priv) {
		PRINT(KERN_ERR, "nic_uio_dev is null!\n");
		return UIO_ERROR;
	}

	handle = priv->ae_handle;
	index  = uio_para.index;

PRINT(KERN_ERR, "cmd: %d\n", cmd);
	
    switch (cmd) {
	case HNS_UIO_IOCTL_MAC:
	{
		memcpy((void *)priv->netdev->dev_addr,
		       (void *)&uio_para.data[0], 6);
		ret = handle->dev->ops->set_mac_addr(handle,
						     priv->netdev->dev_addr);
		if (ret) {
			PRINT(KERN_ERR, "set_mac_addr fail, ret = %d\n", ret);
			return UIO_ERROR;
		}

		break;
	}
	case HNS_UIO_IOCTL_UP:
	{
        //int k;
        priv->link = 0;
	    //netif_start_queue(priv->netdev);	

        ret = handle->dev->ops->start ? handle->dev->ops->start(handle)
		      : 0;

		if (ret) {
			return UIO_ERROR;
		}
		PRINT(KERN_ERR, "q_num=%d", priv->q_num);
        //for(k = 0; k< priv->q_num;k++){
        //    handle->dev->ops->toggle_queue_status(handle->qs[k],1);
        //}
        if(priv->phy)
            phy_start(priv->phy);
		break;
	}
	case HNS_UIO_IOCTL_DOWN:
	{
		if (handle->dev->ops->stop)
			handle->dev->ops->stop(priv->ae_handle);

		break;
	}
	case HNS_UIO_IOCTL_PORT:
	{
		uio_para.value = priv->port;
		if (copy_to_user((void __user *)arg, &uio_para,
				 sizeof(struct hns_uio_ioctrl_para)) != 0)
			return UIO_ERROR;

		break;
	}
	case HNS_UIO_IOCTL_VF_MAX:
	{
		uio_para.value = priv->vf_sum;
		if (copy_to_user((void __user *)arg, &uio_para,
				 sizeof(struct hns_uio_ioctrl_para)) != 0)
			return UIO_ERROR;

		break;
	}
	case HNS_UIO_IOCTL_VF_ID:
	{
		uio_para.value = priv->vf_id;
		if (copy_to_user((void __user *)arg, &uio_para,
				 sizeof(struct hns_uio_ioctrl_para)) != 0)
			return UIO_ERROR;

		break;
	}
	case HNS_UIO_IOCTL_QNUM:
	{
		uio_para.value = priv->q_num;
		if (copy_to_user((void __user *)arg, &uio_para,
				 sizeof(struct hns_uio_ioctrl_para)) != 0)
			return UIO_ERROR;

		break;
	}
	case HNS_UIO_IOCTL_VF_START:
	{
		uio_para.value = priv->uio_start;
		if (copy_to_user((void __user *)arg, &uio_para,
				 sizeof(struct hns_uio_ioctrl_para)) != 0)
			return UIO_ERROR;

		break;
	}
	case HNS_UIO_IOCTL_MTU:
	{
		ret = hns_uio_change_mtu(priv, (int)uio_para.value);
		break;
	}
	case HNS_UIO_IOCTL_GET_STAT:
	{
		unsigned long long *data = kzalloc(
			sizeof(unsigned long long) * 256, GFP_KERNEL);

		hns_uio_get_stats(priv, data);
		if (copy_to_user((void __user *)arg, data, sizeof(data)) != 0)
			return UIO_ERROR;

		break;
	}
	case HNS_UIO_IOCTL_GET_LINK:
		uio_para.value =
			handle->dev->ops->get_status ? handle->dev->ops->
			get_status(handle) : 0;
		if (copy_to_user((void __user *)arg, &uio_para,
				 sizeof(struct hns_uio_ioctrl_para)) != 0)
			return UIO_ERROR;

		break;

	case HNS_UIO_IOCTL_REG_READ:
	{
		struct hnae_queue *queue;

		queue = handle->qs[0];
		uio_para.value = dsaf_read_reg(queue->io_base, uio_para.cmd);
        if (copy_to_user((void __user *)arg, &uio_para,
				 sizeof(struct hns_uio_ioctrl_para)) != 0)
			return UIO_ERROR;

		break;
	}
	case HNS_UIO_IOCTL_REG_WRITE:
	{
		struct hnae_queue *queue;

		queue = handle->qs[0];
		dsaf_write_reg(queue->io_base, uio_para.cmd, uio_para.value);
		uio_para.value = dsaf_read_reg(queue->io_base, uio_para.cmd);
		if (copy_to_user((void __user *)arg, &uio_para,
				 sizeof(struct hns_uio_ioctrl_para)) != 0)
			return UIO_ERROR;

		break;
	}
	case HNS_UIO_IOCTL_SET_PAUSE:
	{
		hns_uio_pausefrm_cfg(priv->vf_cb->mac_cb, 0, uio_para.value);
		break;
	}
    case HNS_UIO_IOCTL_INIT_MAC:
    {
       struct net_device *netdev = priv->netdev;
       
       if (!device_get_mac_address(priv->dev, netdev->dev_addr, ETH_ALEN)){
	        PRINT(KERN_ERR, "no valid mac!\n");
            eth_hw_addr_random(netdev);
       }
       memcpy(uio_para.data, netdev->dev_addr, ETH_ALEN);
	   PRINT(KERN_ERR, "MAC: %02hhx %02hhx %02hhx %02hhx %02hhx %02hhx",
               netdev->dev_addr[0],netdev->dev_addr[1],
               netdev->dev_addr[2],netdev->dev_addr[3],
               netdev->dev_addr[4],netdev->dev_addr[5]);
       if (copy_to_user((void __user *)arg, &uio_para,
			 sizeof(struct hns_uio_ioctrl_para)) != 0)
		    return UIO_ERROR;

       break;
    }
    case HNS_UIO_IOCTL_LINK_UPDATE:
    {
        int state = 1;
        if (priv->phy){
            if (!genphy_update_link(priv->phy))
                state = priv->phy->link;
            else
                state = 0;
        }
        state = state && handle->dev->ops->get_status(handle);

        if(state != priv->link){
            if(state) {
                netif_carrier_on(priv->netdev);
                netif_tx_wake_all_queues(priv->netdev);
                netdev_info(priv->netdev, "link up\n");
            } else{
                netif_carrier_off(priv->netdev);
                netdev_info(priv->netdev, "link down\n");
            }
            priv->link = state;
        }
        break; 
    }
    case HNS_UIO_IOCTL_PROMISCUOUS:
    {
        struct netdev_hw_addr *ha = NULL;
        handle->dev->ops->set_promisc_mode(handle, !!uio_para.value);
        netdev_for_each_mc_addr(ha, priv->netdev)
            if(handle->dev->ops->set_mc_addr(handle,ha->addr))
                netdev_err(priv->netdev, "set multicast fail\n");
        break;
    }
    case HNS_UIO_IOCTL_TSO:
    {
        netif_set_gso_max_size(priv->netdev, 7 * 4096);
        handle->dev->ops->set_tso_stats(handle, !!uio_para.value);
        break;
    
    }
    default:
		PRINT(KERN_ERR, "uio ioctl cmd(%d) illegal! range:0-%d.\n", cmd,
		      HNS_UIO_IOCTL_NUM - 1);
		return UIO_ERROR;
	}

	return ret;
}

const struct file_operations hns_uio_fops = {
	.owner = THIS_MODULE,
	.read  = hns_cdev_read,
	.write = hns_cdev_write,
	.unlocked_ioctl = hns_cdev_ioctl,
	.compat_ioctl	= hns_cdev_ioctl,
};

int hns_uio_register_cdev(void)
{
	struct device *aeclassdev;
	struct char_device *priv = &char_dev;

	if (char_dev_flag++ != 0)
		return UIO_OK;

	(void)strncpy(priv->name, "nic_uio", strlen("nic_uio"));
	priv->major = register_chrdev(0, priv->name, &hns_uio_fops);
	(void)strncpy(priv->class_name, "nic_uio", strlen("nic_uio"));
	priv->dev_class = class_create(THIS_MODULE, priv->class_name);
	if (IS_ERR(priv->dev_class)) {
		PRINT(KERN_ERR, "Class_create device %s failed!\n",
		      priv->class_name);
		(void)unregister_chrdev(priv->major, priv->name);
		return PTR_ERR(priv->dev_class);
	}

	aeclassdev = device_create(priv->dev_class, NULL, MKDEV(priv->major,
								0), NULL,
				   priv->name);
	if (IS_ERR(aeclassdev)) {
		PRINT(KERN_ERR, "Class_device_create device %s failed!\n",
		      priv->class_name);
		(void)unregister_chrdev(priv->major, priv->name);
		class_destroy((void *)priv->dev_class);
		return PTR_ERR(aeclassdev);
	}

	return UIO_OK;
}

void hns_uio_unregister_cdev(void)
{
	struct char_device *priv = &char_dev;

	if (char_dev_flag == 0)
		return;

	if (char_dev_flag == 1) {
		unregister_chrdev(priv->major, priv->name);
		device_destroy(priv->dev_class, MKDEV(priv->major, 0));
		class_destroy(priv->dev_class);
	}

	char_dev_flag--;
}

/*static int hns_nic_phy_match(struct device *dev, void *phy_fwnode)
{
    if (IS_ENABLED(CONFIG_OF) && dev->of_node)
        return &dev->of_node->fwnode == phy_fwnode;
    else if (ACPI_COMPANION(dev))
        return dev->fwnode == phy_fwnode;
    else
        return 0;
}*/

/*
static
struct phy_device *hns_nic_phy_find_device(struct fwnode_handle *phy_fwnode)
{
	struct device *d;

	if (!phy_fwnode)
		return NULL;

	d = bus_find_device(&mdio_bus_type, NULL,
			    phy_fwnode, hns_nic_phy_match);

	return d ? to_phy_device(d) : NULL;
}
*/

/*
static
struct phy_device *hns_nic_phy_attach(struct net_device *dev,
				      struct fwnode_handle *phy_fwnode,
				      u32 flags,
				      phy_interface_t iface)
{
	struct phy_device *phy = hns_nic_phy_find_device(phy_fwnode);
	int ret;

	if (!phy)
		return NULL;

	ret = phy_attach_direct(dev, phy, flags, iface);

	return ret ? NULL : phy;
}

static
struct phy_device *hns_nic_phy_connect(struct net_device *dev,
				       struct fwnode_handle *phy_fwnode,
				       void (*hndlr)(struct net_device *),
				       u32 flags,
				       phy_interface_t iface)
{
	struct phy_device *phy = hns_nic_phy_find_device(phy_fwnode);
	int ret;

	if (!phy)
		return NULL;

	phy->dev_flags = flags;

	ret = phy_connect_direct(dev, phy, hndlr, iface);


	put_device(&phy->dev); 

	return ret ? NULL : phy;
} */

static int hns_uio_nic_open(struct uio_info *dev_info, struct inode *node)
{
	/* PRINT("hns_uio_nic_open = 0x%llx\n", dev_info->mem[0].addr); */
	return UIO_OK;
}

static int hns_uio_nic_release(struct uio_info *dev_info,
			       struct inode    *inode)
{
	return UIO_OK;
}

static int hns_uio_nic_irqcontrol(struct uio_info *dev_info, s32 irq_state)
{
	PRINT(KERN_ERR, "hns_uio_nic_open = %d\n", irq_state);
	return UIO_OK;
}

static irqreturn_t hns_uio_nic_irqhandler(int irq,
					  struct uio_info *dev_info)
{
	struct rte_uio_platform_dev *priv = dev_info->priv;

	uio_event_notify(&priv->info);
	PRINT(KERN_ERR, "hns_uio_nic_open = %d\n", irq);
	return IRQ_HANDLED;
}



/**
 * Template to r/w something
 */
static ssize_t
show_something(struct device *dev, struct device_attribute *attr,
                 char *buf)
{
    return 0;
}

static ssize_t
store_something(struct device *dev, struct device_attribute *attr,
                  const char *buf, size_t count)
{
    int err = 0;

    return err ? err : count;
}

static DEVICE_ATTR(something, S_IRUGO | S_IWUSR, show_something, store_something);

static struct attribute *dev_attrs[] = {
    &dev_attr_something.attr,
    NULL,
};

static const struct attribute_group dev_attr_grp = {
    .attrs = dev_attrs,
};



/* Remap platform resources described by index in uio resource n. */
static int
hnsuio_setup_iomem(struct platform_device *dev, struct uio_info *info,
		       int n, int index, const char *name)
{
	unsigned long addr, len;
	void *internal_addr;

	if (n >= ARRAY_SIZE(info->mem))
		return -EINVAL;

	addr = platform_resource_start(dev, index);
	len = platform_resource_len(dev, index);
	if (len == 0)
		return -EINVAL;
	
    internal_addr = ioremap(addr, len);
	if (internal_addr == NULL)
		return -1;
	info->mem[n].name = name;
	info->mem[n].addr = addr;
	info->mem[n].internal_addr = internal_addr;
	info->mem[n].size = len;
	info->mem[n].memtype = UIO_MEM_PHYS;
	return 0;
}

/* Get platform port io resources described by index in uio resource n. */
static int
hnsuio_setup_ioport(struct platform_device *dev, struct uio_info *info,
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
hnsuio_release_iomem(struct uio_info *info)
{
	int i;

	for (i = 0; i < MAX_UIO_MAPS; i++) {
		if (info->mem[i].internal_addr)
			iounmap(info->mem[i].internal_addr);
	}
}

static int
hnsuio_remap_memory(struct platform_device *dev, struct uio_info *info)
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

    printk(KERN_DEBUG "There is %d resources\n", num_res);
    for(i=0; i<num_res; i++) {
        if(platform_resource_len(dev, i)!=0 &&
                platform_resource_start(dev, i)!=0) {
            flags = platform_resource_flags(dev, i);

            printk(KERN_DEBUG "resource %d has flag %d\n", i, (int)flags);
            if(flags & IORESOURCE_MEM){
                ret = hnsuio_setup_iomem(dev, info, iom, i, bar_names[i]);
                if(ret!=0)
                    return ret;
                iom++;
            }
            else if(flags & IORESOURCE_IO) {
                ret = hnsuio_setup_ioport(dev, info, iop, i, bar_names[i]);
                if(ret!=0)
                    return ret;
                iop++;
            }
           
        }
    }
    return 0;
}

 static void hns_nic_adjust_link(struct net_device *netdev)
{
	struct rte_uio_platform_dev *priv = netdev_priv(netdev);
	struct hnae_handle *h = priv->ae_handle;
	int state = 1;

	if (netdev->phydev) {
		h->dev->ops->adjust_link(h, netdev->phydev->speed,
					 netdev->phydev->duplex);
		state = netdev->phydev->link;
	}
	state = state && h->dev->ops->get_status(h);

	if (state != priv->link) {
		if (state) {
			netif_carrier_on(netdev);
			netif_tx_wake_all_queues(netdev);
			netdev_info(netdev, "link up\n");
		} else {
			netif_carrier_off(netdev);
			netdev_info(netdev, "link down\n");
		}
		priv->link = state;
	}
} 

static int 
hns_nic_init_phy(struct net_device *netdev, struct hnae_handle *h)
{
	struct phy_device *phy_dev = h->phy_dev;
	int ret;

	if (!h->phy_dev)
		return 0;

	if (h->phy_if != PHY_INTERFACE_MODE_XGMII) {
		phy_dev->dev_flags = 0;

		ret = phy_connect_direct(netdev, phy_dev, hns_nic_adjust_link,
					 h->phy_if);
	} else {
		ret = phy_attach_direct(netdev, phy_dev, 0, h->phy_if);
	}
	if (unlikely(ret))
		return -ENODEV;

	phy_dev->supported &= h->if_support;
	phy_dev->advertising = phy_dev->supported;

	if (h->phy_if == PHY_INTERFACE_MODE_XGMII)
		phy_dev->autoneg = false;

	return 0;
}

void hns_free_buffers(struct hnae_ring *ring)
{
    int i;
    for(i = 0; i < ring->desc_num; i++)
        hnae_free_buffer_detach(ring, i);
}

void hns_free_desc(struct hnae_ring *ring)
{
    hns_free_buffers(ring);
    dma_unmap_single(ring_to_dev(ring), ring->desc_dma_addr,
            ring->desc_num * sizeof(ring->desc[0]), ring_to_dma_dir(ring));
    ring->desc_dma_addr = 0;
    kfree(ring->desc);
    ring->desc = NULL;
}

/* fini ring, also free the buffer for the ring */
void hns_fini_ring(struct hnae_ring *ring)
{
    hns_free_desc(ring);
    kfree(ring->desc_cb);
    ring->desc_cb = NULL;
    ring->next_to_clean = 0;
    ring->next_to_use = 0;
}

void hns_kernel_queue_free(struct hnae_handle *handle)
{
    int i;
    struct hnae_queue *q;
    
    for(i =0; i < handle->q_num; i++){
        q = handle->qs[i];
        if(q->dev->ops->fini_queue)
            q->dev->ops->fini_queue(q);

        hns_fini_ring(&q->tx_ring);
        hns_fini_ring(&q->rx_ring);
    }       
}

int hns_user_queue_malloc(struct hnae_handle *handle)
{
    int i;
    struct hnae_ring *tx_ring;
    struct hnae_ring *rx_ring;
    unsigned char *base_tx_cb;
    unsigned char *base_rx_cb;
    unsigned char *base_tx_desc;
    unsigned char *base_rx_desc;
    dma_addr_t base_tx_dma;
    dma_addr_t base_rx_dma;
    int cb_size;
    int desc_size;

    tx_ring = (struct hnae_ring *)&handle->qs[0]->tx_ring;
    rx_ring = (struct hnae_ring *)&handle->qs[0]->rx_ring;
    cb_size = tx_ring->desc_num * sizeof(tx_ring->desc_cb[0]);
    desc_size = tx_ring->desc_num * sizeof(tx_ring->desc[0]);

    base_tx_cb = kcalloc(handle->q_num, cb_size, GFP_KERNEL);
    if (!base_tx_cb)
        return UIO_ERROR;

    base_rx_cb = kcalloc(handle->q_num, cb_size, GFP_KERNEL);
    if(!base_rx_cb)
        goto fail_free_tx_cb;

    base_tx_desc = kzalloc(desc_size * handle->q_num, GFP_KERNEL);
    if(!base_tx_desc)
        goto fail_free_rx_cb;
 
    base_tx_dma = dma_map_single(ring_to_dev(tx_ring), base_tx_desc,
            desc_size * handle->q_num, ring_to_dma_dir(tx_ring));
    if(dma_mapping_error(ring_to_dev(tx_ring), base_tx_dma))
        goto fail_free_tx_desc;

    base_rx_desc = kzalloc(desc_size * handle->q_num, GFP_KERNEL);
    if(!base_tx_desc)
        goto fail_free_tx_desc;

    base_rx_dma = dma_map_single(ring_to_dev(rx_ring), base_rx_desc,
            desc_size * handle->q_num, ring_to_dma_dir(rx_ring));
    if(dma_mapping_error(ring_to_dev(rx_ring), base_rx_dma))
        goto fail_unmap_tx_dma;

    for(i = 0; i < handle->q_num; i++){
        tx_ring = (struct hnae_ring *)&handle->qs[i]->tx_ring;
        rx_ring = (struct hnae_ring *)&handle->qs[i]->rx_ring;
        tx_ring->q = handle->qs[i];
        tx_ring->flags = 1;
        rx_ring->q = handle->qs[i];
        rx_ring->flags = 0;
        
        tx_ring->desc_cb = 
            (struct hnae_desc_cb *)(base_tx_cb + cb_size *i);
        rx_ring->desc_cb = 
            (struct hnae_desc_cb *)(base_rx_cb + cb_size * i);
        tx_ring->desc = 
            (struct hnae_desc *)(base_tx_desc + desc_size *i);
        rx_ring->desc = 
            (struct hnae_desc *)(base_rx_desc + desc_size * i);
        tx_ring->desc_dma_addr = base_tx_dma + desc_size * i;
        rx_ring->desc_dma_addr = base_rx_dma + desc_size * i;

        if(handle->dev->ops->init_queue)
            handle->dev->ops->init_queue(handle->qs[i]);
    }
    return UIO_OK;

fail_unmap_tx_dma:
    dma_unmap_single(ring_to_dev(tx_ring), base_tx_dma,
            desc_size * handle->q_num, ring_to_dma_dir(tx_ring));
fail_free_tx_desc:
    kfree(base_tx_desc);
fail_free_rx_cb:
    kfree(base_rx_cb);
fail_free_tx_cb:
    kfree(base_tx_cb);
    return UIO_ERROR;
}


int hns_user_queue_free(struct hnae_handle *handle)
{
    int i;
    struct hnae_ring *tx_ring = (struct hnae_ring *)&handle->qs[0]->tx_ring;
    struct hnae_ring *rx_ring = (struct hnae_ring *)&handle->qs[0]->rx_ring;

    kfree(rx_ring->desc);
    kfree(tx_ring->desc);
    kfree(rx_ring->desc_cb);
    kfree(tx_ring->desc_cb);

    dma_unmap_single(ring_to_dev(tx_ring), tx_ring->desc_dma_addr,
            tx_ring->desc_num * sizeof(tx_ring->desc[0]) * handle->q_num,
                ring_to_dma_dir(tx_ring));
    
    dma_unmap_single(ring_to_dev(rx_ring), rx_ring->desc_dma_addr,
            rx_ring->desc_num * sizeof(rx_ring->desc[0]) * handle->q_num,
                ring_to_dma_dir(rx_ring));

    for(i = 0; i < handle->q_num; i++){
        tx_ring = (struct hnae_ring *)&handle->qs[i]->tx_ring;
        rx_ring = (struct hnae_ring *)&handle->qs[i]->rx_ring;
        tx_ring->desc_cb = NULL;
        rx_ring->desc_cb = NULL;
        tx_ring->desc = NULL;
        rx_ring->desc = NULL;
        tx_ring->desc_dma_addr = 0;
        rx_ring->desc_dma_addr = 0;
    }
    return UIO_OK;
}

void hnae_list_del(spinlock_t	    *lock,
		   struct list_head *node)
{
	unsigned long flags;

	spin_lock_irqsave(lock, flags);
	list_del_rcu(node);
	spin_unlock_irqrestore(lock, flags);
}

void hns_user_put_handle(struct hnae_handle *h)
{
	struct hnae_ae_dev *dev = h->dev;

	hns_user_queue_free(h);

	if (h->dev->ops->reset)
		h->dev->ops->reset(h);

	hnae_list_del(&dev->lock, &h->node);

	if (dev->ops->put_handle)
		dev->ops->put_handle(h);

	module_put(dev->owner);
}

static int hns_uio_alloc(struct hnae_ring *ring, struct hnae_desc_cb *cb)
{
   return UIO_OK;
}

static void hns_uio_free(struct hnae_ring *ring, struct hnae_desc_cb *cb)
{
}

static int hns_uio_map(struct hnae_ring *ring, struct hnae_desc_cb *cb)
{
	return UIO_OK;
}

static void hns_uio_unmap(struct hnae_ring *ring, struct hnae_desc_cb *cb)
{
}

static struct hnae_buf_ops hns_uio_nic_bops = {
	.alloc_buffer = hns_uio_alloc,
	.free_buffer  = hns_uio_free,
	.map_buffer   = hns_uio_map,
	.unmap_buffer = hns_uio_unmap,
};

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 8, 0)
static int __devinit
#else
static int
#endif
hns_uio_probe(struct platform_device *pdev)
{
    struct rte_uio_platform_dev *udev;
    struct hnae_handle *handle;
    struct device *dev = &pdev->dev;
    struct net_device *netdev;
    struct hnae_queue *queue;
    struct hnae_vf_cb *vf_cb;
    struct acpi_device *adev = to_acpi_device_node(dev->fwnode);
    struct acpi_reference_args args;
    const struct fwnode_handle *fwnode;

    int port = 0, uio_start = uio_index, i, queue_mode;
    static int cards_found;
    int err;
    (void)adev;
    (void)hnsuio_release_iomem;
    (void)hnsuio_remap_memory;
    
    /* get acpi_reference_args */
    err = acpi_node_get_property_reference(dev->fwnode,
            "ae-handle", 0, &args);
    if (err){
        dev_err(dev, "not find ae-handle\n");
        return err;
    }
    
    fwnode = acpi_fwnode_handle(args.adev);

    /* get port-id */
    err = device_property_read_u32(dev, "port-idx-in-ae", &port);
    if (err){
        err = device_property_read_u32(dev, "port-id", &port);
        if(err)
            return err;
    }
   
    PRINT(KERN_ERR,"get here\n");
    do {
        /* get handle */
        handle = hnae_get_handle(dev, fwnode, port, &hns_uio_nic_bops);
        PRINT(KERN_DEBUG,"get handle: %lx\n", (unsigned long)handle);

        if(IS_ERR_OR_NULL(handle)){
            dev_dbg(dev, "get handle error");
            goto fail_free_dev;
        }

        hns_kernel_queue_free(handle);
        err = hns_user_queue_malloc(handle);

        vf_cb = (struct hnae_vf_cb *)container_of(
                handle, struct hnae_vf_cb, ae_handle);

        if(IS_ERR_OR_NULL(vf_cb)){
            PRINT(KERN_ERR,"vf_cb error: %lx\n",(unsigned long)vf_cb);
            goto fail_get_handle;
        }
        netdev = alloc_etherdev_mq(sizeof(struct rte_uio_platform_dev),
                handle->q_num);
        if(!netdev) {
            printk("alloc_etherdev_mq fail\n");
            goto fail_get_handle;
        }

        udev = netdev_priv(netdev);
        udev->dev = dev;
        udev->netdev = netdev;
        udev->ae_handle = handle;
        udev->vf_cb = vf_cb;
        udev->port = port;
        udev->vf_sum = port_vf[vf_cb->dsaf_dev->dsaf_mode];
        udev->vf_id = handle->vf_id;
   
        udev->q_num = handle->q_num;
        PRINT(KERN_ERR,"qnum:%d\n",udev->q_num);
        udev->uio_start = uio_start;

        queue = handle->qs[0];
        udev->info.name = DRIVER_UIO_NAME;
        udev->info.version = "1";
        udev->info.priv = (void *)udev;
        
        udev->info.mem[0].name = "rcb ring";
        udev->info.mem[0].addr = (unsigned long)queue->phy_base;
        udev->info.mem[0].size = NIC_UIO_SIZE * handle->q_num;
        udev->info.mem[0].memtype = UIO_MEM_PHYS;
        
        udev->info.mem[1].name = "tx_bd";
        udev->info.mem[1].addr = (unsigned long)queue->tx_ring.desc;
        udev->info.mem[1].size = queue->tx_ring.desc_num * 
                            sizeof(queue->tx_ring.desc[0]) *
                            handle->q_num;
        PRINT(KERN_ERR,"total desc in tx:%d\n",queue->tx_ring.desc_num);
        udev->info.mem[1].memtype = UIO_MEM_LOGICAL;

        udev->info.mem[2].name = "rx_bd";
        udev->info.mem[2].addr = (unsigned long)queue->rx_ring.desc;
        udev->info.mem[2].size = queue->rx_ring.desc_num * 
                            sizeof(queue->rx_ring.desc[0]) *
                            handle->q_num;
        PRINT(KERN_ERR,"total desc in rx:%d\n",queue->rx_ring.desc_num);
        udev->info.mem[2].memtype = UIO_MEM_LOGICAL;

        udev->info.mem[3].name = "nic_uio_device";
        udev->info.mem[3].addr = (unsigned long)(uio_index);
        udev->info.mem[3].size = sizeof(unsigned long);
        udev->info.mem[3].memtype = UIO_MEM_LOGICAL;
       
        udev->info.irq_flags = UIO_IRQ_CUSTOM;
        udev->info.handler = hns_uio_nic_irqhandler;
        udev->info.irqcontrol = hns_uio_nic_irqcontrol;
        udev->info.open = hns_uio_nic_open;
        udev->info.release = hns_uio_nic_release;
        
        err = uio_register_device(dev, &udev->info);
        if (err) {
            PRINT (KERN_ERR, "uio_register_device failed!\n");
            goto fail_unregister_uio;
        }

        platform_set_drvdata(pdev, netdev);
        uio_dev_info[uio_index] = udev;

        netdev_assign_netdev_ops(netdev);
        hns_ethtool_set_ops(netdev);
        SET_NETDEV_DEV(netdev, dev);

        err = hns_nic_init_phy(netdev, handle);
        if(err){
            PRINT(KERN_ERR, "cannot init phy");
            goto fail_unregister_uio;
        }

        strcpy(netdev->name, "odp%d");
        udev->bd_number = cards_found;
        netdev->ifindex = cards_found;
        err = register_netdev(netdev);
        if (err)
            goto fail_unregister_uio;

        memset(&udev->nstats, 0, sizeof(struct net_device_stats));
        udev->netdev_registered = true;

        uio_index++;
        PRINT(KERN_DEBUG,"uio_index now is %d\n",uio_index);
        queue_mode = hns_uio_get_queue_mode(vf_cb->dsaf_dev->dsaf_mode);
        PRINT(KERN_DEBUG, "queue_mode: %d\n",queue_mode);
    } while(handle->vf_id < (queue_mode-1));
    //for test==========================================================
    //i = 0;
    //do {
    //    test = hnae_get_handle(dev, fwnode, port, &hns_uio_nic_bops);
    //    PRINT(KERN_DEBUG, "get handle: %lx\n", (unsigned long)test);
    //    i++;
    //} while (i<10 && handle->vf_id < (port_vf[vf_cb->dsaf_dev->dsaf_mode] - 1));
    //-----------------------------------------------------------------

    err = hns_uio_register_cdev();
    if(err){
        PRINT(KERN_ERR,
                "registering the character device failed! ret=%d\n", err);
        goto fail_free_dev;
    }
    
    return UIO_OK;

fail_unregister_uio:
    free_netdev(udev->netdev);
fail_get_handle:
    hns_user_put_handle(handle);
fail_free_dev:
    for(i=0;i<uio_index;i++){
        udev = uio_dev_info[i];
        uio_unregister_device(&udev->info);
        free_netdev(udev->netdev);
        hns_user_put_handle(udev->ae_handle);
        uio_dev_info[i] = NULL;
    }
    return err;
}

static int
hns_uio_remove(struct platform_device *dev)
{
 
    int i=0, vf_max=0;
    struct net_device *netdev = platform_get_drvdata(dev);
    struct rte_uio_platform_dev *udev = netdev_priv(netdev);
    struct rte_uio_platform_dev *priv;

    hns_uio_unregister_cdev();

    PRINT(KERN_ERR, "vf_sum = %d, uio_start = %d, q_num = %d\n",
             udev->vf_sum, udev->uio_start, udev->q_num);

    vf_max = udev->uio_start+udev->vf_sum;
    for(i = udev->uio_start;i<vf_max;i++){
        priv = uio_dev_info[i];
        if (!priv)
            continue;
        uio_unregister_device(&priv->info);

        if(priv->netdev_registered){
            unregister_netdev(priv->netdev);
            priv->netdev_registered = false;
        }

        if(priv->ae_handle->dev->ops->stop)
            priv->ae_handle->dev->ops->stop(priv->ae_handle);

        if (priv->phy)
            phy_disconnect(priv->phy);
        free_netdev(priv->netdev);
        hns_user_put_handle(priv->ae_handle);
        uio_dev_info[i] = NULL;
    }

    /*
    struct rte_uio_platform_dev *udev = platform_get_drvdata(dev);

    sysfs_remove_group(&dev->dev.kobj, &dev_attr_grp);
    uio_unregister_device(&udev->info);
    platform_set_drvdata(dev,NULL);
    kfree(udev);
*/
    return 0;
}
/*
static int
hns_probe2(struct platform_device *pdev)
{
    (void)pdev;
    (void)hns_uio_probe;
    return 0;
}

static int
hns_remove2(struct platform_device *pdev)
{
    (void)pdev;
    (void)hns_uio_remove;
    return 0;
}*/

int hns_uio_suspend(struct platform_device *pdev,
        pm_message_t state)
{
    return UIO_OK;
}

int hns_uio_resume(struct platform_device *pdev)
{
    return UIO_OK;
}

static const struct acpi_device_id hns_enet_acpi_match[] = {
    {"HISI00C1", 0 },
    {"HISI00C2", 0 },
    {},
};

MODULE_DEVICE_TABLE(acpi, hns_enet_acpi_match);

/*
static const struct of_device_id hns_enet_of_match[] = {
    {.compatible = "hisilicon,hns-nic-v1",},
    {.compatible = "hisilicon,hns-nic-v2",},
    {},
};

MODULE_DEVICE_TABLE(of, hns_enet_of_match);
*/

static struct platform_driver hns_uio_driver = {
    .probe = hns_uio_probe,
    .remove = hns_uio_remove,
//    .probe = hns_probe2,
//    .remove = hns_remove2,
    .suspend = hns_uio_suspend,
    .resume = hns_uio_resume,
    .driver = 
    {
        .owner = THIS_MODULE,
        .name = "hns_uio",
//        .of_match_table = hns_enet_of_match,
        .acpi_match_table = ACPI_PTR(hns_enet_acpi_match),
        .suppress_bind_attrs = false,
    },
};

static int __init
hnsuio_init_module(void)
{
    uio_index = 0;
    char_dev_flag = 0; 
    return platform_driver_register(&hns_uio_driver);
}

static void __exit
hnsuio_exit_module(void)
{
    platform_driver_unregister(&hns_uio_driver);
}

module_init(hnsuio_init_module);
module_exit(hnsuio_exit_module);

MODULE_DESCRIPTION("UIO driver for Arm platform");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("LAB 1219");
