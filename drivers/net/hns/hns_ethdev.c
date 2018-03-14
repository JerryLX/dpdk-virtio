#include <sys/queue.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include <stdint.h>
#include <stdarg.h>
#include <unistd.h>
#include <rte_common.h>
#include <rte_interrupts.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_mbuf.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_eal.h>
#include <rte_atomic.h>
#include <rte_malloc.h>
#include <rte_dev.h>
#include <rte_platform.h>
#include <rte_ethdev_platform.h>
#include "hns_ethdev.h"
#include "hns_logs.h"
#include <arm_neon.h>
/*
 * The set of Platform devices this driver supports
 */
static const struct rte_platform_id platform_id_hns_map[] = {
    {.name = "HISI00C2:07"},
    {.name = "HISI00C2:06"},
    {.name = "HISI00C2:05"},
    {.name = "HISI00C2:04"},
    {.name = "HISI00C2:03"},
    {.name = "HISI00C2:02"},
    {0},
};
#define I40E_VPMD_DESC_DD_MASK  0x8000800080008000ULL

//prefetch function
#if 1
#define RTE_PMD_USE_PREFETCH
#endif

#ifdef RTE_PMD_USE_PREFETCH
#define rte_hns_prefetch(p)	rte_prefetch0(p)
#else
#define rte_hns_prefetch(p)	do {} while(0)
#endif

#ifdef RTE_PMD_PACKET_PREFETCH
#define rte_packet_prefetch(p) rte_prefetch1(p)
#endif

#ifdef OPTIMIZATION
#undef OPTIMIZATION
#endif

static void
get_v2rx_desc_bnum(uint32_t bnum_flag, uint16_t *out_bnum)
{
    *out_bnum = hnae_get_field(bnum_flag,
            HNS_RXD_BUFNUM_M, HNS_RXD_BUFNUM_S) + 1;
}

//static bool
//is_fe(uint32_t flag)
//{
//    return ((flag & (1 << HNS_RXD_FE_B)) != 0);
//}

/**
 * Read value from q->iobase
 * rxtx:
 *      0 for rx 1 for tx
 */
static int
reg_read(void *io_base, unsigned long long offset, uint16_t queue_id, bool rxtx)
{
    char *addr = io_base;
    addr += (offset+HNS_RCB_REG_OFFSET*(queue_id));
    if(rxtx) addr+=HNS_RCB_TX_REG_OFFSET;
    
    return *(const volatile uint32_t *)addr;
}

/**
 * Write value to q->iobase
 * rxtx:
 *      0 for rx 1 for tx
 */
static void
reg_write(void *io_base, unsigned long long offset, uint16_t queue_id, 
        bool rxtx, unsigned long long value)
{
    char *addr = io_base;
    addr += (offset+HNS_RCB_REG_OFFSET*(queue_id));
    if(rxtx) addr+=HNS_RCB_TX_REG_OFFSET;
    *(uint32_t *)addr = value;
   // rte_wmb();
}

//static int
//dsaf_reg_read(unsigned int uio_index, unsigned long long offset, 
//         int fd, uint16_t queue_id, bool rxtx)
//{
//    struct hns_uio_ioctrl_para args;
//    args.index = uio_index;
//    args.cmd = offset + HNS_RCB_REG_OFFSET * (queue_id);
//    if(rxtx) args.cmd += HNS_RCB_TX_REG_OFFSET;
//    if(ioctl(fd, HNS_UIO_IOCTL_REG_READ, &args) < 0) {
//        PMD_INIT_LOG(ERR, "get value failed, offset: %llu\n!", offset);
//        return -EINVAL;
//    }
//    return args.value;
//}
//
//static int
//dsaf_reg_write(unsigned int uio_index, unsigned long long offset,
//        unsigned long long value, int fd, uint16_t queue_id, bool rxtx)
//{
//    struct hns_uio_ioctrl_para args;
//    args.index = uio_index;
//    args.cmd = offset + HNS_RCB_REG_OFFSET * (queue_id);
//    if(rxtx) args.cmd += HNS_RCB_TX_REG_OFFSET;
//    args.value = value;
//    if(ioctl(fd, HNS_UIO_IOCTL_REG_WRITE, &args) < 0) {
//        printf("write error!\n");
//        PMD_INIT_LOG(ERR, "write value failed, offset: %llu\n!", offset);
//        return -EINVAL;
//    }
//    return 0;
//}

static void
hns_dev_free_queues(struct rte_eth_dev *dev)
{
    uint16_t i;
    for(i = 0; i<dev->data->nb_rx_queues; i++){
        eth_hns_rx_queue_release(dev->data->rx_queues[i]);
        dev->data->rx_queues[i] = NULL;
    }
    for(i = 0; i<dev->data->nb_tx_queues; i++){
        eth_hns_tx_queue_release(dev->data->tx_queues[i]);
        dev->data->tx_queues[i] = NULL;
    }
}

static int
eth_hns_reta_update(struct rte_eth_dev *dev, 
        struct rte_eth_rss_reta_entry64 *reta_conf,
        uint16_t reta_size)
{
    (void) dev;
    (void) reta_conf;
    (void) reta_size;
    return 0;
}

static int
eth_hns_reta_query(struct rte_eth_dev *dev,
        struct rte_eth_rss_reta_entry64 *reta_conf,
        uint16_t reta_size)
{
    (void) dev;
    (void) reta_conf;
    (void) reta_size;
    return 0;
}


static const uint32_t *
eth_hns_supported_ptypes_get(struct rte_eth_dev *dev)
{
	static const uint32_t ptypes[] = {
		/* refers to i40e_rxd_pkt_type_mapping() */
		RTE_PTYPE_L2_ETHER,
		RTE_PTYPE_L2_ETHER_TIMESYNC,
		RTE_PTYPE_L2_ETHER_LLDP,
		RTE_PTYPE_L2_ETHER_ARP,
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN,
		RTE_PTYPE_L3_IPV6_EXT_UNKNOWN,
		RTE_PTYPE_L4_FRAG,
		RTE_PTYPE_L4_ICMP,
		RTE_PTYPE_L4_NONFRAG,
		RTE_PTYPE_L4_SCTP,
		RTE_PTYPE_L4_TCP,
		RTE_PTYPE_L4_UDP,
		RTE_PTYPE_TUNNEL_GRENAT,
		RTE_PTYPE_TUNNEL_IP,
		RTE_PTYPE_INNER_L2_ETHER,
		RTE_PTYPE_INNER_L2_ETHER_VLAN,
		RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN,
		RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN,
		RTE_PTYPE_INNER_L4_FRAG,
		RTE_PTYPE_INNER_L4_ICMP,
		RTE_PTYPE_INNER_L4_NONFRAG,
		RTE_PTYPE_INNER_L4_SCTP,
		RTE_PTYPE_INNER_L4_TCP,
		RTE_PTYPE_INNER_L4_UDP,
		RTE_PTYPE_UNKNOWN
	};
    (void) dev;
		return ptypes;
}

/**
 * DPDK callback to start the device.
 *
 */
static int
eth_hns_start(struct rte_eth_dev *dev)
{
    struct hns_adapter *hns = dev->data->dev_private;
    struct hns_uio_ioctrl_para args;
	//printf("eth_hns_start\n");
    int uio_index = hns->uio_index;
    args.index = uio_index;
    if(ioctl(hns->cdev_fd, HNS_UIO_IOCTL_MAC, &args) < 0) {
        PMD_INIT_LOG(ERR, "Set mac addr failed!");
        return -EINVAL;
    }
	//printf("ioctl_MAC\n");
    if(ioctl(hns->cdev_fd, HNS_UIO_IOCTL_UP, &args) < 0) {
        PMD_INIT_LOG(ERR, "Open dev failed!");
        return -EINVAL;
    }
    //printf("Open dev success!\n");
    return 0;
}

static void
eth_hns_mac_addr_set(struct rte_eth_dev *dev, struct ether_addr *addr)
{
    struct hns_adapter *hns = dev->data->dev_private;
    struct hns_uio_ioctrl_para args;
    int uio_index = hns->uio_index;
    args.index = uio_index;
    memcpy((void *)&args.data[0],
           (void *)&addr->addr_bytes[0],6);
    if(ioctl(hns->cdev_fd, HNS_UIO_IOCTL_MAC, &args) < 0) {
        PMD_INIT_LOG(ERR, "Set mac addr failed!");
    }
}

static void
eth_hns_stop(struct rte_eth_dev *dev)
{
    struct hns_adapter *hns = dev->data->dev_private;
    struct hns_uio_ioctrl_para args;
    int uio_index = hns->uio_index;

    args.index = uio_index;
    if(ioctl(hns->cdev_fd, HNS_UIO_IOCTL_DOWN, &args) < 0) {
        PMD_INIT_LOG(ERR, "Stop dev failed!");
    }
}

static void
eth_hns_close(struct rte_eth_dev *dev)
{   
    struct hns_adapter *hns = dev->data->dev_private;
    eth_hns_stop(dev);
    hns->stopped = 1;
    hns_dev_free_queues(dev);
}

static int
eth_hns_link_update(struct rte_eth_dev *dev, int wait_to_complete)
{
    struct hns_adapter *hns = dev->data->dev_private;
    struct hns_uio_ioctrl_para args;
    int uio_index = hns->uio_index;
    struct rte_eth_link *res;
    
    (void) wait_to_complete;
    args.index = uio_index;
    if(ioctl(hns->cdev_fd, HNS_UIO_IOCTL_LINK_UPDATE, &args) < 0) {
        PMD_INIT_LOG(ERR, "Get link status failed\n");
        return -EINVAL;
    }
    //printf("get link success!\n");
    res = (struct rte_eth_link *)args.data;
    printf("new link speed: %u, new duples: %u,new autoneg: %u, new status: %u", 
            res->link_speed,res->link_duplex, res->link_autoneg, res->link_status);

    if(memcmp(res, &dev->data->dev_link, sizeof(struct rte_eth_link))){
        dev->data->dev_link.link_speed = res->link_speed;
        dev->data->dev_link.link_duplex = res->link_duplex;
        dev->data->dev_link.link_autoneg = res->link_autoneg;
        dev->data->dev_link.link_status = res->link_status;
        return -1;
    }
    (void) dev;
    (void) wait_to_complete;
    return 0;

}

static int
eth_hns_set_mtu(struct rte_eth_dev *dev, uint16_t mtu)
{
    printf("-----------set mtu here!--------------\n");
    struct hns_adapter *hns = dev->data->dev_private;
    struct hns_uio_ioctrl_para args;
    int uio_index = hns->uio_index;

    args.index = uio_index;
    args.value = (unsigned int) mtu;
    if(ioctl(hns->cdev_fd, HNS_UIO_IOCTL_MTU, &args) < 0) {
        PMD_INIT_LOG(ERR, "Set mtu failed!");
        return -EINVAL;
    }
    return 0;
}

static void
eth_hns_stats_reset(struct rte_eth_dev *dev)
{
    struct hns_adapter *hns = dev->data->dev_private;
    struct hns_stats *stats = &(hns->stats);
    memset(stats, 0, sizeof(struct hns_stats));
}

static void
eth_hns_stats_get(struct rte_eth_dev *dev, struct rte_eth_stats *rte_stats)
{
    struct hns_adapter *hns = dev->data->dev_private;
//    int uio_index = hns->uio_index;
//    unsigned long long p[256];
//    struct hns_uio_ioctrl_para *args = 
//        (struct hns_uio_ioctrl_para *)p;
//
//    args->index = uio_index;
//    if(ioctl(hns->cdev_fd, HNS_UIO_IOCTL_GET_STAT, p) < 0) {
//        PMD_INIT_LOG(ERR, "Get stat failed!");
//    }
//
//    rte_stats->ipackets  = p[0];
//    rte_stats->opackets  = p[1];
//    rte_stats->ibytes    = p[2];
//    rte_stats->obytes    = p[3];
//    rte_stats->imissed   = p[6];
//    rte_stats->ierrors   = p[4];
//    rte_stats->oerrors   = p[5];
    struct hns_stats *stats = &(hns->stats);
    rte_stats->ipackets  = stats->rx_pkts;
    rte_stats->opackets  = stats->tx_pkts;
    rte_stats->ibytes    = stats->rx_bytes;
    rte_stats->obytes    = stats->tx_bytes;
    rte_stats->ierrors   = stats->rx_err_cnt;
    rte_stats->oerrors   = stats->tx_err_cnt;
}

/**
 * DPDK callback to get information about the device.
 *
 * @param dev
 *      Pointer to Ethernet device structure.
 * @param[out] info
 *      Info structure output buffer.
 */
static void
eth_hns_dev_infos_get(struct rte_eth_dev *dev, struct rte_eth_dev_info *info)
{
    struct hns_adapter *hns = dev->data->dev_private;

    info->max_rx_queues = hns->q_num;
    info->max_tx_queues = hns->q_num;
    info->max_rx_pktlen = 9600;
    info->min_rx_bufsize = 256;
    
	info->rx_offload_capa =
		 (DEV_RX_OFFLOAD_IPV4_CKSUM |
		  DEV_RX_OFFLOAD_UDP_CKSUM |
		  DEV_RX_OFFLOAD_TCP_CKSUM);
	
	info->tx_offload_capa =
		 (DEV_TX_OFFLOAD_IPV4_CKSUM |
		  DEV_TX_OFFLOAD_UDP_CKSUM |
		  DEV_TX_OFFLOAD_TCP_CKSUM);

    info->speed_capa = ETH_LINK_SPEED_10M_HD | ETH_LINK_SPEED_10M |
			ETH_LINK_SPEED_100M_HD | ETH_LINK_SPEED_100M |
			ETH_LINK_SPEED_1G;
	
    info->rx_desc_lim.nb_max = hns->desc_num_per_rxq;
    info->rx_desc_lim.nb_max = hns->desc_num_per_txq;
//    info->nb_rx_queues = hns->q_num;
//    info->nb_tx_queues = hns->q_num;
    info->vmdq_queue_num = 1;
}

static int
eth_hns_configure(struct rte_eth_dev *dev)
{
    (void) dev;
    return 0;
}

static void
eth_hns_allmulticast_enable(struct rte_eth_dev *dev)
{
    (void) dev;
}

/**
 * Enable promiscuous mode
 */
static void
eth_hns_promisc_enable(struct rte_eth_dev *dev)
{
    struct hns_adapter *hns = dev->data->dev_private;
    struct hns_uio_ioctrl_para args;
    int uio_index = hns->uio_index;

    args.index = uio_index;
    args.value = 1;
    if(ioctl(hns->cdev_fd, HNS_UIO_IOCTL_PROMISCUOUS, &args) < 0) {
        PMD_INIT_LOG(ERR, "Enable promisc mode failed!");
        printf("enable promisc failed\n");
    }
    printf("enable promisc\n");
}

/**
 * Disable promiscuous mode
 */
static void
eth_hns_promisc_disable(struct rte_eth_dev *dev)
{
    struct hns_adapter *hns = dev->data->dev_private;
    struct hns_uio_ioctrl_para args;
    int uio_index = hns->uio_index;

    args.index = uio_index;
    args.value = 0;
    if(ioctl(hns->cdev_fd, HNS_UIO_IOCTL_PROMISCUOUS, &args) < 0) {
        PMD_INIT_LOG(ERR, "Disable promisc mode failed!");
    }
}

/**
 * Enable TSO mode
 */
static void
eth_hns_tso_enable(struct rte_eth_dev *dev)
{
    struct hns_adapter *hns = dev->data->dev_private;
    struct hns_uio_ioctrl_para args;
    int uio_index = hns->uio_index;
    hns->tso = 1;
    args.index = uio_index;
    args.value = 1;
    if(ioctl(hns->cdev_fd, HNS_UIO_IOCTL_TSO, &args) < 0) {
        PMD_INIT_LOG(ERR, "Enable TSO mode failed!");
    }
    printf("enable tso\n");
}

/**
 * Disable TSO mode
 */
static void
eth_hns_tso_disable(struct rte_eth_dev *dev)
{
    struct hns_adapter *hns = dev->data->dev_private;
    struct hns_uio_ioctrl_para args;
    int uio_index = hns->uio_index;
    hns->tso = 0;
    args.index = uio_index;
    args.value = 0;
    if(ioctl(hns->cdev_fd, HNS_UIO_IOCTL_TSO, &args) < 0) {
        PMD_INIT_LOG(ERR, "Disable TSO mode failed!");
    }
}

/********************************************
 *
 *  Receive unit
 *
 * *****************************************/
static void
hns_rx_queue_release_mbufs(struct hns_rx_queue *rxq)
{
    unsigned i;

    if(rxq->sw_ring != NULL){
        for(i = 0; i < rxq->nb_rx_desc; i++) {
            if(rxq->sw_ring[i].mbuf != NULL){
                rte_pktmbuf_free_seg(rxq->sw_ring[i].mbuf);
                rxq->sw_ring[i].mbuf = NULL;
            }
        }
    }
}

/**
 * DPDK call back to release a RX queue
 *
 * @param rxq
 *      RX queue pointer
 *
 */
void
eth_hns_rx_queue_release(void *queue) {
    if(queue != NULL){
        struct hns_rx_queue *rxq = queue;

//#ifdef OPTIMIZATION
//        struct rte_mbuf *bufs[256];
//        int num, i;
//        num = rte_ring_dequeue_burst(rxq->cache_ring, (void **)bufs, 256);
//        for(i=0;i<num;i++){
//            bufs[i]->cache_ring = NULL;
//            rte_pktmbuf_free_seg(bufs[i]);
//        }
//#endif
        hns_rx_queue_release_mbufs(rxq);
        rte_free(rxq->sw_ring);
        rte_free(rxq);

    }
}

static inline uint32_t
rxd_pkt_info_to_pkt_type(uint32_t pkt_info)
{
    uint32_t pkt_type = 0;
    uint32_t l3id, l4id;

    static const uint32_t l3table[16] = {
        RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4,
        RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6,
        RTE_PTYPE_L2_ETHER_ARP,
        RTE_PTYPE_L2_ETHER,
        RTE_PTYPE_L2_ETHER,
        RTE_PTYPE_L2_ETHER,
        RTE_PTYPE_L2_ETHER_LLDP,
        0,0,0,0,0,0,0,0,0
    };

    static const uint32_t l4table[16] = {
        RTE_PTYPE_L4_UDP,
        RTE_PTYPE_L4_TCP,
        RTE_PTYPE_TUNNEL_GRE,
        RTE_PTYPE_L4_SCTP,
        0,
        RTE_PTYPE_L4_ICMP,
        0,0,0,0,0,0,0,0,0,0
    };
    
    l3id = hnae_get_field(pkt_info, HNS_RXD_L3ID_M, HNS_RXD_L3ID_S);
    l4id = hnae_get_field(pkt_info, HNS_RXD_L4ID_M, HNS_RXD_L4ID_S);
    pkt_type |= (l3table[l3id] | l4table[l4id]);
    
    return pkt_type;
}

static inline uint64_t
rx_desc_status_to_pkt_flags(uint32_t rx_status)
{
    uint64_t pkt_flags;

    pkt_flags = ((rx_status & HNS_RXD_VLAN_M) ?
            PKT_RX_VLAN_PKT | PKT_RX_VLAN_STRIPPED : 0);

    return pkt_flags;
}


static inline uint64_t
rx_desc_error_to_pkt_flags(uint32_t rx_status)
{
    uint64_t pkt_flags = 0;

    if(hnae_get_bit(rx_status, HNS_RXD_L4E_B))
        pkt_flags |= PKT_RX_L4_CKSUM_BAD;

    if(hnae_get_bit(rx_status, HNS_RXD_L3E_B))
        pkt_flags |= PKT_RX_IP_CKSUM_BAD;

    return pkt_flags;
}
/**
 * Local function to alloc rx buffers.
 *
 * @param rxq
 *      RX queue pointer
 * @param cleand_count
 *      Number of cleaned desc
 *
 */
static void
hns_clean_rx_buffers(struct hns_rx_queue *rxq, int cleaned_count)
{
    struct hns_adapter *hns = rxq->hns;
    int qid = rxq->queue_id;

    rxq->next_to_use += cleaned_count;
    if(rxq->next_to_use >= rxq->nb_rx_desc)
        rxq->next_to_use -= rxq->nb_rx_desc;
    reg_write(hns->io_base, RCB_REG_HEAD, qid,0,cleaned_count);
}

/**
 * DPDK callback to configure a RX queue
 *
 * @param dev
 *      Pointer to Ethernet device structure.
 * @param idx
 *      RX queue index.
 * @param nb_desc
 *      Number of descriptors to configure in queue.
 * @param socket
 *      NUMA socket on which memory must be allocated.
 * @param[in] conf
 *      Thresholds parameters.
 * @param mp
 *      Memory pool for buffer allocations.
 *
 * @return
 *      0 on success, negative errno value on failure.
 *
 */
#define DEFAULT_RX_FREE_THRESH 16
static int
eth_hns_rx_queue_setup(struct rte_eth_dev *dev, uint16_t idx, uint16_t nb_desc,
        unsigned int socket, const struct rte_eth_rxconf *conf,
        struct rte_mempool *mp)
{
    struct hns_adapter *hns = dev->data->dev_private;
    struct hns_rx_queue *rxq;
    int i;

//#ifdef OPTIMIZATION
//    char cache_ring_name[64];
//#endif

    (void) socket;
    (void) nb_desc;
    if(dev->data->rx_queues[idx] != NULL){
        eth_hns_rx_queue_release(dev->data->rx_queues[idx]);
        dev->data->rx_queues[idx] = NULL;
    } 

    rxq = rte_zmalloc("ethdev RX queue", sizeof(struct hns_rx_queue),
            RTE_CACHE_LINE_SIZE);
    if(rxq == NULL){
        //printf("no space for rx_queue\n");
        return -ENOMEM;
    }
    rxq->mb_pool = mp;
    rxq->nb_rx_desc = hns->desc_num_per_rxq;
    rxq->queue_id = idx;
    rxq->rx_ring = hns->rx_desc[idx];

    if(conf == NULL || conf->rx_free_thresh <= 0)
        rxq->rx_free_thresh = DEFAULT_RX_FREE_THRESH;
    else
        rxq->rx_free_thresh = conf->rx_free_thresh;

    dev->data->rx_queues[idx] = rxq;

    rxq->sw_ring = rte_zmalloc("rxq->sw_ring",
            sizeof(struct hns_rx_entry) * rxq->nb_rx_desc,
            RTE_CACHE_LINE_SIZE);
    if(rxq->sw_ring == NULL){
        //printf("no space for sw_ring\n");
        eth_hns_rx_queue_release(rxq);
        return -ENOMEM;
    }
    
//#ifdef OPTIMIZATION
//    snprintf(cache_ring_name, 64, "Port%d RXQ%d Cache",dev->data->port_id, idx);
//    printf("%s\n",cache_ring_name);
//    rxq->cache_ring = rte_ring_create(cache_ring_name, 256, socket, 0);
//    for(i = 0; i < 256; i++){
//        struct rte_mbuf *mbuf = rte_mbuf_raw_alloc(rxq->mb_pool);
//        if(!mbuf){
//            printf("no more mbuf!\n");
//            return -1;
//        }
//        mbuf->cache_ring = rxq->cache_ring;
//        rte_ring_enqueue(rxq->cache_ring,(void *)mbuf);
//    }
//#endif
    for(i = 0;i<rxq->nb_rx_desc;i++){
        struct rte_mbuf *mbuf = rte_mbuf_raw_alloc(rxq->mb_pool);
        if(!mbuf){
            printf("no more mbuf!\n");
            return -1;
        }
        
//#ifdef OPTIMIZATION
//        mbuf->cache_ring = rxq->cache_ring;
//#endif
        rxq->sw_ring[i].mbuf = mbuf;
    }


    PMD_INIT_LOG(DEBUG, "sw_ring=%p", rxq->sw_ring);
    rxq->next_to_use = 0;
    rxq->next_to_clean = 0;
    rxq->nb_rx_hold = 0;
    rxq->pkt_first_seg = NULL;
    rxq->pkt_last_seg = NULL;
    rxq->hns = hns;
    rxq->port_id = dev->data->port_id; 
    return 0;
}

/**
 * DPDK callback for RX.
 *
 * @param rx_queue
 *   Generic pointer to RX queue structure.
 * @param[out] rx_pkts
 *   Array to store received packets.
 * @param nb_pkts
 *   Maximum number of packets in array.
 *
 * @return
 *   Number of packets successfully received (<= nb_pkts).
 */
static inline void
hns_rxq_realloc_mbuf(struct hns_rx_queue *rx_queue,uint16_t idx){
	struct hns_rx_queue *rxq;       //RX queue 
    struct hnae_desc *rx_ring;      //RX ring (desc)
    struct hns_rx_entry *sw_ring;
	struct rte_mbuf *nmb;           //pointer of the new mbuf
	uint64_t dma_addr;
    rxq = rx_queue;
	int i;
	for( i=0;i<4;i++){
		sw_ring = &rxq->sw_ring[idx+i];
		rx_ring = &rxq->rx_ring[idx+i];
		nmb = rte_mbuf_raw_alloc(rxq->mb_pool);
        if (nmb == NULL){
            PMD_RX_LOG(DEBUG, "RX mbuf alloc failed port_id=%u "
                        "queue_id=%u", (unsigned) rxq->port_id,
                        (unsigned) rxq->queue_id);
            rte_eth_devices[rxq->port_id].data->rx_mbuf_alloc_failed++;
            break;
        }
		sw_ring->mbuf = nmb;
		dma_addr = 
            //rte_cpu_to_le_64(rte_mbuf_data_dma_addr_default(rxm));
            rte_cpu_to_le_64(rte_mbuf_data_dma_addr_default(nmb));
        rx_ring->addr = dma_addr;
	}
	
}

//收包函数，收取nb_pkts个描述符，如果某个描述符对应着分片的包，就按顺序在split_packet数组对应位置填上标记位
static inline uint16_t
_recv_raw_pkts_vec(struct hns_rx_queue *rx_queue, struct rte_mbuf **rx_pkts,
		   uint16_t nb_pkts, uint8_t *split_packet)
{
	struct hnae_desc *rx_ring;
	struct hns_rx_entry *sw_ring;
	uint16_t nb_pkts_recd;
	uint16_t rx_id;
	uint64_t var;
	int num;  //能用的描述符的个数
	int nb_hold;//用了的描述符个数
	struct hns_adapter *hns;
	struct hns_rx_queue *rxq;
	/* mask to shuffle from desc. to mbuf */  
	uint8x16_t shuf_msk = {
		0xFF, 0xFF,   /* pkt_type set as unknown */
		0xFF, 0xFF,   /* pkt_type set as unknown */
		12, 13,       /* low 16 bits pkt_len */
		0xFF, 0xFF,   
		14, 15,       /* 16 bits data_len */
		0xFF, 0xFF,         /* vlan set as unknown */
		0xFF, 0xFF, 0xFF, 0xFF    /* rss set as unknown*/
		};  
		
	
	/*判断描述符是否对应的分片了的包*/ 
	uint8x16_t split_check = {
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x40, 0x00, 0x40,
		0x00, 0x40, 0x00, 0x40
		};
    
	rxq = rx_queue;
	rx_id = rxq->next_to_clean;
    rx_ring = rxq->rx_ring;
	sw_ring = rxq->sw_ring;
	nb_hold = 0;
    //get num of packets in desc ring
    hns = rxq->hns;
    num = reg_read(hns->io_base, RCB_REG_FBDNUM, rxq->queue_id, 0);
    int count=0;
	/*开始收取，每次4个*/
	for (nb_hold = 0, nb_pkts_recd = 0; (nb_hold < nb_pkts) && (count < num) ;
			nb_hold += 4,
			rx_id=((rx_id + 4)>= rxq->nb_rx_desc)?0:rx_id+4) {
		uint64x2_t descs[4];
		uint8x16_t pkt_mb1, pkt_mb2, pkt_mb3, pkt_mb4;
		uint16x8x2_t sterr_tmp1, sterr_tmp2;
		uint64x2_t mbp1, mbp2;
		uint16x8_t staterr;
		uint16_t data_len;
		uint64_t stat;
	    (void) stat;	
		count+=4;
		
		
		/* B.1 load 1 mbuf point */
		mbp1 = vld1q_u64((uint64_t *)&sw_ring[rx_id]);                     		//取出两个mbuf指针
		
		/* Read desc statuses backwards to avoid race condition */
		/* A.1 load 4 pkts desc */
		descs[3] =  vld1q_u64(((uint64_t *)&rx_ring[rx_id+3]));                        //描述符信息加载，128bit，不要hns描述符前64地址位和最后32位的保留位就是128位
		rte_rmb();                                     

		/* B.2 copy 2 mbuf point into rx_pkts  */                    
		vst1q_u64((uint64_t *)&rx_pkts[nb_hold], mbp1);                           //把获取的mbuf指针存到指定位置，每次循环存4个

		/* B.1 load 1 mbuf point */                                           
		mbp2 = vld1q_u64((uint64_t *)&sw_ring[rx_id + 2]);                      

		descs[2] =  vld1q_u64(((uint64_t *)&rx_ring[rx_id+2]));
		/* B.1 load 2 mbuf point */
		descs[1] =  vld1q_u64(((uint64_t *)&rx_ring[rx_id+1]));
		descs[0] =  vld1q_u64(((uint64_t *)&rx_ring[rx_id]));

		/* B.2 copy 2 mbuf point into rx_pkts  */
		vst1q_u64((uint64_t *)&rx_pkts[nb_hold + 2], mbp2);
		
		//然后重新分配下这四个用了的mbuf
		hns_rxq_realloc_mbuf(rxq,rx_id);
		
		if (split_packet) {
			rte_mbuf_prefetch_part2(rx_pkts[nb_hold]);
			rte_mbuf_prefetch_part2(rx_pkts[nb_hold + 1]);
			rte_mbuf_prefetch_part2(rx_pkts[nb_hold + 2]);
			rte_mbuf_prefetch_part2(rx_pkts[nb_hold + 3]);
		}

		/* avoid compiler reorder optimization */
		rte_compiler_barrier();                                               //这个不知道干嘛的。。。照着写。
		
		/* pkt 3,4 shift the pktlen field to be 16-bit aligned
		
		int32x4_t len_shl = {0, 0, 0, PKTLEN_SHIFT};                          //这个用于16-bit aligned，没怎么看懂...
		uint32x4_t len3 = vshlq_u32(vreinterpretq_u32_u64(descs[3]),
					    len_shl);
		descs[3] = vreinterpretq_u64_u32(len3);
		uint32x4_t len2 = vshlq_u32(vreinterpretq_u32_u64(descs[2]),
					    len_shl);
		descs[2] = vreinterpretq_u64_u32(len2); */                            //----------这段对齐的作用还没搞清楚,不知道对应该怎么改。
		
		
		/* D.1 pkt 3,4 convert format from desc to pktmbuf */
		pkt_mb4 = vqtbl1q_u8(vreinterpretq_u8_u64(descs[3]), shuf_msk);
		pkt_mb3 = vqtbl1q_u8(vreinterpretq_u8_u64(descs[2]), shuf_msk);       //开始对描述符字段进行重排列，排出来为[0,0,0,0,pktlen,pktlen,0,0,data_len,data_len,0,0,0,0,0,0]
		
		data_len = vgetq_lane_u16(vreinterpretq_u16_u8(pkt_mb4),4);
		hns->stats.rx_bytes += data_len;
		data_len = vgetq_lane_u16(vreinterpretq_u16_u8(pkt_mb3),4);           //hns_adapter里的数据需要设置一下
		hns->stats.rx_bytes += data_len;
		
		/* C.1 4=>2 filter staterr info only */
		sterr_tmp2 = vzipq_u16(vreinterpretq_u16_u64(descs[3]),
				       vreinterpretq_u16_u64(descs[1]));
		/* C.1 4=>2 filter staterr info only */
		sterr_tmp1 = vzipq_u16(vreinterpretq_u16_u64(descs[0]),
				       vreinterpretq_u16_u64(descs[2]));
		
		/* C.2 get 4 pkts staterr value  */                                 
		staterr = vzipq_u16(sterr_tmp1.val[1],                               //这里得到的staterr为[l0,l1,l2,l3,h0,h1,h2,h3]
				    sterr_tmp2.val[1]).val[0];                               //其中l代表一个描述符的ipoff_bnum_pid_flag字段低16位，h代表高16位，包含VALID有效标志，和FRAG（是否为分片标志）
		stat = vgetq_lane_u64(vreinterpretq_u64_u16(staterr), 1);            //stat就是[h0,h1,h2,h3]
		
		
		/* pkt 1,2 shift the pktlen field to be 16-bit aligned
		uint32x4_t len1 = vshlq_u32(vreinterpretq_u32_u64(descs[1]),
					    len_shl);
		descs[1] = vreinterpretq_u64_u32(len1);
		uint32x4_t len0 = vshlq_u32(vreinterpretq_u32_u64(descs[0]),
					    len_shl);
		descs[0] = vreinterpretq_u64_u32(len0);*/              		        //还是那个对齐操作，又来了。。
		
		/* D.1 pkt 1,2 convert format from desc to pktmbuf */
		pkt_mb2 = vqtbl1q_u8(vreinterpretq_u8_u64(descs[1]), shuf_msk);
		pkt_mb1 = vqtbl1q_u8(vreinterpretq_u8_u64(descs[0]), shuf_msk);
		
		data_len = vgetq_lane_u16(vreinterpretq_u16_u8(pkt_mb2),4);
		hns->stats.rx_bytes += data_len;
		data_len = vgetq_lane_u16(vreinterpretq_u16_u8(pkt_mb1),4);
		hns->stats.rx_bytes += data_len;                                     //hns_adapter里的数据需要设置一下
		
        /* D.3 copy final 3,4 data to rx_pkts */
		vst1q_u8((void *)&rx_pkts[nb_hold + 3]->rx_descriptor_fields1,
				 pkt_mb4);
		vst1q_u8((void *)&rx_pkts[nb_hold + 2]->rx_descriptor_fields1,           //把pkt_mb：包含了pkt_len和data_len的信息存入mbuf描述符区域
				 pkt_mb3);
		
				 
		//开始检查4个描述符是否是分片的
		/* C* extract and record EOP bit */
		if (split_packet) {
			uint8x16_t eop_shuf_mask = {
					0x09, 0x0B, 0x0D, 0x0F,
					0xFF, 0xFF, 0xFF, 0xFF,
					0xFF, 0xFF, 0xFF, 0xFF,
					0xFF, 0xFF, 0xFF, 0xFF};
			uint8x16_t eop_bits;

			/* and with mask to extract bits, flipping 1-0 */
			eop_bits = vreinterpretq_u8_u16(staterr);
			eop_bits = vandq_u8(eop_bits, split_check);
			/* the staterr values are not in order, as the count
			 * count of dd bits doesn't care. However, for end of
			 * packet tracking, we do care, so shuffle. This also
			 * compresses the 32-bit values to 8-bit
			 */
			eop_bits = vqtbl1q_u8(eop_bits, eop_shuf_mask);      //把4个获得的分片标志位(每个是uint8_t移到一起，uint32_t)

			/* store the resulting 32-bit value */
			vst1q_lane_u32((uint32_t *)split_packet,
				       vreinterpretq_u32_u8(eop_bits), 0);
			split_packet += 4;
			/* zero-out next pointers */
			rx_pkts[nb_hold]->next = NULL;
			rx_pkts[nb_hold + 1]->next = NULL;
			rx_pkts[nb_hold + 2]->next = NULL;
			rx_pkts[nb_hold + 3]->next = NULL;
		}

//		rte_prefetch_non_temporal(rx_ring + 4);
		/* D.3 copy final 1,2 data to rx_pkts */
		vst1q_u8((void *)&rx_pkts[nb_hold + 1]->rx_descriptor_fields1,
			 pkt_mb2);
		vst1q_u8((void *)&rx_pkts[nb_hold]->rx_descriptor_fields1,        //把后两个mbuf相关信息也存入
			 pkt_mb1);
	    rx_pkts[nb_hold + 0]->data_off = RTE_PKTMBUF_HEADROOM;	
	    rx_pkts[nb_hold + 1]->data_off = RTE_PKTMBUF_HEADROOM;	
	    rx_pkts[nb_hold + 2]->data_off = RTE_PKTMBUF_HEADROOM;	
	    rx_pkts[nb_hold + 3]->data_off = RTE_PKTMBUF_HEADROOM;	
		/* C.4 calc avaialbe number of desc */
		//var = __builtin_popcountll(stat & I40E_VPMD_DESC_DD_MASK);    //计算这一轮收了几个有效包，如果小于4个，break
        //printf("var=%d",(int)var);
        (void) var;
        nb_pkts_recd += 4;
		//if (likely(var != 4))
		//	break;
	}
	
	/* Update 数据 */
		
    rxq->next_to_clean = rx_id;
	hns_clean_rx_buffers(rxq, nb_hold);

	
	return nb_pkts_recd;
		
	
}



static inline uint16_t
reassemble_packets(struct hns_rx_queue *rxq, struct rte_mbuf **rx_bufs,
		   uint16_t nb_bufs, uint8_t *split_flags)
{
	struct rte_mbuf *pkts[32]; /*finished pkts*/ //这个放入最终的muf，然后拷贝到目标 rx_bufs当中去
	struct rte_mbuf *start = rxq->pkt_first_seg;
	struct rte_mbuf *end =  rxq->pkt_last_seg;
	unsigned pkt_idx, buf_idx;

	for (buf_idx = 0, pkt_idx = 0; buf_idx < nb_bufs; buf_idx++) {
		if (end != NULL) {
			/* processing a split packet */
			end->next = rx_bufs[buf_idx];
			//rx_bufs[buf_idx]->data_len += rxq->crc_len;

			start->nb_segs++;
			start->pkt_len += rx_bufs[buf_idx]->data_len;
			end = end->next;

			if (!split_flags[buf_idx]) {
				/* it's the last packet of the set */
				/*start->hash = end->hash;
				start->ol_flags = end->ol_flags; */ 
				pkts[pkt_idx++] = start;
				start = end = NULL;
			}
		} else {
			/* not processing a split packet */
			if (!split_flags[buf_idx]) {
				/* not a split packet, save and skip */
				pkts[pkt_idx++] = rx_bufs[buf_idx];
				continue;
			}
			end = start = rx_bufs[buf_idx];
		}
	}

	/* save the partial packet for next time */
	rxq->pkt_first_seg = start;
	rxq->pkt_last_seg = end;
	memcpy(rx_bufs, pkts, pkt_idx * (sizeof(*pkts)));
	return pkt_idx;
}


static uint16_t eth_hns_recv_pkts(void *rx_queue, struct rte_mbuf **rx_pkts, uint16_t nb_pkts)
{
	 struct hns_rx_queue *rxq;       //RX queue 
    struct hnae_desc *rx_ring;      //RX ring (desc)
    struct hns_rx_entry *sw_ring;
    struct hns_rx_entry *rxe;
    struct hnae_desc *rxdp;         //pointer of the current desc
    struct rte_mbuf *first_seg;
    struct rte_mbuf *last_seg;
    struct hnae_desc rxd;           //current desc
    struct rte_mbuf *nmb;           //pointer of the new mbuf
    struct rte_mbuf *rxm;
    struct hns_adapter *hns;

    uint64_t dma_addr;
    uint16_t rx_id;
    uint16_t nb_hold;
	uint16_t nb_rx;
    uint16_t data_len;
    uint16_t pkt_len;
    int num;                   //num of desc in ring
    uint16_t bnum;
    uint32_t bnum_flag;
    uint16_t current_num;
    int length;

//#ifdef OPTIMIZATION
//    void *nmb_buf[1];
//#endif
   // uint8_t ip_offset;
//    unsigned long long value;

    nb_rx  =0;
    nb_hold = 0;
	rxq = rx_queue;
    hns = rxq->hns;
    rx_id = rxq->next_to_clean;
    rx_ring = rxq->rx_ring;
    first_seg = rxq->pkt_first_seg;
    last_seg = rxq->pkt_last_seg;
    current_num = rxq->current_num;
    sw_ring = rxq->sw_ring;
    //get num of packets in desc ring
    num = reg_read(hns->io_base, RCB_REG_FBDNUM, rxq->queue_id, 0);
    while(nb_rx < nb_pkts && nb_hold < num ){
        //printf("recv in queue:%d\n",num);
next_desc:
        if((rx_id & 0x3) == 0){
            rte_hns_prefetch(&rx_ring[rx_id]);
            rte_hns_prefetch(&sw_ring[rx_id]);
        }
        rxdp = &rx_ring[rx_id];
        rxd = *rxdp;
        rxe = &sw_ring[rx_id];

        nmb = rte_mbuf_raw_alloc(rxq->mb_pool);
        if (nmb == NULL){
            PMD_RX_LOG(DEBUG, "RX mbuf alloc failed port_id=%u "
                        "queue_id=%u", (unsigned) rxq->port_id,
                        (unsigned) rxq->queue_id);
            rte_eth_devices[rxq->port_id].data->rx_mbuf_alloc_failed++;
            break;
        }
        nb_hold++;
        rx_id++;
        if(rx_id == rxq->nb_rx_desc) {
            rx_id = 0;
        }
        
        bnum_flag = rte_le_to_cpu_32(rxd.rx.ipoff_bnum_pid_flag);
        length = rte_le_to_cpu_16(rxd.rx.pkt_len); 
        get_v2rx_desc_bnum(bnum_flag, &bnum);
        


        rte_hns_prefetch(rxe->mbuf);
        rxm = rxe->mbuf;
        rxe->mbuf = nmb;

        dma_addr = 
            //rte_cpu_to_le_64(rte_mbuf_data_dma_addr_default(rxm));
            rte_cpu_to_le_64(rte_mbuf_data_dma_addr_default(nmb));
        rxdp->addr = dma_addr;

        if(  first_seg == NULL){
            //this is the first seg
            first_seg = rxm;
            first_seg-> nb_segs = bnum;
            first_seg->vlan_tci = 
                rte_le_to_cpu_16(hnae_get_field(rxd.rx.vlan_cfi_pri,HNS_RXD_VLANID_M, HNS_RXD_VLANID_S));
            if(length <= HNS_RX_HEAD_SIZE){
                if(unlikely(bnum != 1)){
                    goto pkt_err;
                }
            } else{
                if(unlikely(bnum >= (int)MAX_SKB_FRAGS)){
                    goto pkt_err;
                } 
            }
            current_num = 1;
        }else{
            //this is not the first seg
            last_seg->next = rxm;
        }
        
        pkt_len = (uint16_t) (rte_le_to_cpu_16(rxd.rx.pkt_len));
        data_len = (uint16_t) (rte_le_to_cpu_16(rxd.rx.size)); 
        rxm->data_off = RTE_PKTMBUF_HEADROOM;
        rxm->data_len = data_len;
        rxm->pkt_len = pkt_len;
        //printf("data_len:%d,%d\n",data_len,pkt_len);
        rxm->port = rxq->port_id;
        rxm->hash.rss = rxd.rx.rss_hash;
        
        hns->stats.rx_bytes += data_len;

        if(current_num < bnum) {
            last_seg = rxm;
            current_num++;
            goto next_desc;
        }
        hns->stats.rx_pkts++;
        bnum_flag = rte_le_to_cpu_32(rxd.rx.ipoff_bnum_pid_flag);
       // ip_offset=rte_le_to_cpu_16(hnae_get_field(rxd.rx.ipoff_bnum_pid_flag,HNS_RXD_IPOFFSET_M, HNS_RXD_IPOFFSET_S));
       // printf("RX ip offset= %u",ip_offset);
        //if(unlikely(!hnae_get_bit(bnum_flag, HNS_RXD_VLD_B))) goto pkt_err;
        //if(unlikely((!rxd.rx.pkt_len) || hnae_get_bit(bnum_flag, HNS_RXD_DROP_B))) goto pkt_err;
        //if(unlikely(hnae_get_bit(bnum_flag, HNS_RXD_L2E_B))) goto pkt_err;
        
        rxm->next = NULL;
        //rte_packet_prefetch((char *)first_seg->buf_addr + first_seg->data_off);
        first_seg->packet_type = rxd_pkt_info_to_pkt_type(rxd.rx.ipoff_bnum_pid_flag);
        rx_pkts[nb_rx++] = first_seg;
        first_seg = NULL;
        continue;
        //current_num=0;

       // ip_offset=rte_le_to_cpu_16(hnae_get_field(rxd.rx.ipoff_bnum_pid_flag,HNS_RXD_IPOFFSET_M, HNS_RXD_IPOFFSET_S));
       // printf("RX ip offset= %u",ip_offset);
        //if(unlikely(!hnae_get_bit(bnum_flag, HNS_RXD_VLD_B))) goto pkt_err;
        //if(unlikely((!rxd.rx.pkt_len) || hnae_get_bit(bnum_flag, HNS_RXD_DROP_B))) goto pkt_err;
        //if(unlikely(hnae_get_bit(bnum_flag, HNS_RXD_L2E_B))) goto pkt_err;
pkt_err:
        printf("pkt err in recv\n");
        rte_pktmbuf_free_seg(rxm);
        first_seg = NULL;
    }
    rxq->next_to_clean = rx_id;
    rxq->pkt_first_seg = first_seg;
    rxq->pkt_last_seg = last_seg;
    rxq->current_num = current_num;
    hns_clean_rx_buffers(rxq, nb_hold);
    return nb_rx;
    
//    if(1){
//    struct hns_rx_queue *rxq;       //RX queue 
//    struct hnae_desc *rx_ring;      //RX ring (desc)
//    struct hns_rx_entry *sw_ring;
//    struct hns_rx_entry *rxe;
//    struct hnae_desc *rxdp;         //pointer of the current desc
//    struct rte_mbuf *first_seg;
//    struct rte_mbuf *last_seg;
//    struct hnae_desc rxd;           //current desc
//    struct rte_mbuf *nmb;           //pointer of the new mbuf
//    struct rte_mbuf *rxm;
//    struct hns_adapter *hns;
//
//    uint64_t dma_addr;
//    uint16_t rx_id;
//    uint16_t nb_hold;
//	uint16_t nb_rx;
//    uint16_t data_len;
//    uint16_t pkt_len;
//    int num;                   //num of desc in ring
//    uint16_t bnum;
//    uint32_t bnum_flag;
//    uint16_t current_num;
//    int length;
//
////#ifdef OPTIMIZATION
////    void *nmb_buf[1];
////#endif
//   // uint8_t ip_offset;
////    unsigned long long value;
//
//    nb_rx  =0;
//    nb_hold = 0;
//	rxq = rx_queue;
//    hns = rxq->hns;
//    rx_id = rxq->next_to_clean;
//    rx_ring = rxq->rx_ring;
//    first_seg = rxq->pkt_first_seg;
//    last_seg = rxq->pkt_last_seg;
//    current_num = rxq->current_num;
//    sw_ring = rxq->sw_ring;
//    //get num of packets in desc ring
//    num = reg_read(hns->io_base, RCB_REG_FBDNUM, rxq->queue_id, 0);
//    while(nb_rx < nb_pkts && nb_hold < num ){
//        //printf("recv in queue:%d\n",num);
//next_desc:
//        
//        if((rx_id & 0x3) == 0){
//            rte_hns_prefetch(&rx_ring[rx_id]);
//            rte_hns_prefetch(&sw_ring[rx_id]);
//        }
//        rxdp = &rx_ring[rx_id];
//        rxd = *rxdp;
//        rxe = &sw_ring[rx_id];
//
//        nmb = rte_mbuf_raw_alloc(rxq->mb_pool);
//        if (nmb == NULL){
//            PMD_RX_LOG(DEBUG, "RX mbuf alloc failed port_id=%u "
//                        "queue_id=%u", (unsigned) rxq->port_id,
//                        (unsigned) rxq->queue_id);
//            rte_eth_devices[rxq->port_id].data->rx_mbuf_alloc_failed++;
//            break;
//        }
//        nb_hold++;
//        rx_id++;
//        if(rx_id == rxq->nb_rx_desc) {
//            rx_id = 0;
//        }
//        
//        bnum_flag = rte_le_to_cpu_32(rxd.rx.ipoff_bnum_pid_flag);
//        length = rte_le_to_cpu_16(rxd.rx.pkt_len); 
//        get_v2rx_desc_bnum(bnum_flag, &bnum);
//        
//      /*  if((rx_id & 0x3) == 0){
//            rte_hns_prefetch(&rx_ring[rx_id]);
//            rte_hns_prefetch(&sw_ring[rx_id]);
//        }*/
//
//        rte_hns_prefetch(rxe->mbuf);
//       // rte_hns_prefetch(sw_ring[rx_id].mbuf);
//        rxm = rxe->mbuf;
//        rxe->mbuf = nmb;
//
//        dma_addr = 
//            //rte_cpu_to_le_64(rte_mbuf_data_dma_addr_default(rxm));
//            rte_cpu_to_le_64(rte_mbuf_data_dma_addr_default(nmb));
//        rxdp->addr = dma_addr;
//
//        if(first_seg == NULL){
//            //this is the first seg
//            first_seg = rxm;
//            first_seg-> nb_segs = bnum;
//            first_seg->vlan_tci = 
//                rte_le_to_cpu_16(hnae_get_field(rxd.rx.vlan_cfi_pri,HNS_RXD_VLANID_M, HNS_RXD_VLANID_S));
//            if(length <= HNS_RX_HEAD_SIZE){
//                if(unlikely(bnum != 1)){
//                    goto pkt_err;
//                }
//            } else{
//                if(unlikely(bnum >= (int)MAX_SKB_FRAGS)){
//                    goto pkt_err;
//                } 
//            }
//            current_num = 1;
//        }else{
//            //this is not the first seg
//            last_seg->next = rxm;
//        }
//        
//        /* Initialize the returned mbuf */
//        pkt_len = (uint16_t) (rte_le_to_cpu_16(rxd.rx.pkt_len));
//        data_len = (uint16_t) (rte_le_to_cpu_16(rxd.rx.size)); 
//        rxm->data_off = RTE_PKTMBUF_HEADROOM;
//        rxm->data_len = data_len;
//        rxm->pkt_len = pkt_len;
//        //printf("data_len:%d,%d\n",data_len,pkt_len);
//        rxm->port = rxq->port_id;
//        rxm->hash.rss = rxd.rx.rss_hash;
//        
//        hns->stats.rx_bytes += data_len;
//
//        if(current_num < bnum) {
//            last_seg = rxm;
//            current_num++;
//            goto next_desc;
//        }
//        hns->stats.rx_pkts++;
//        bnum_flag = rte_le_to_cpu_32(rxd.rx.ipoff_bnum_pid_flag);
//       // ip_offset=rte_le_to_cpu_16(hnae_get_field(rxd.rx.ipoff_bnum_pid_flag,HNS_RXD_IPOFFSET_M, HNS_RXD_IPOFFSET_S));
//       // printf("RX ip offset= %u",ip_offset);
//        //if(unlikely(!hnae_get_bit(bnum_flag, HNS_RXD_VLD_B))) goto pkt_err;
//        //if(unlikely((!rxd.rx.pkt_len) || hnae_get_bit(bnum_flag, HNS_RXD_DROP_B))) goto pkt_err;
//        //if(unlikely(hnae_get_bit(bnum_flag, HNS_RXD_L2E_B))) goto pkt_err;
//        
//        rxm->next = NULL;
//        //rte_packet_prefetch((char *)first_seg->buf_addr + first_seg->data_off);
//        first_seg->packet_type = rxd_pkt_info_to_pkt_type(rxd.rx.ipoff_bnum_pid_flag);
//        rx_pkts[nb_rx++] = first_seg;
//        first_seg = NULL;
//        continue;
//pkt_err:
//        printf("pkt err in recv\n");
//        rte_pktmbuf_free_seg(rxm);
//        first_seg = NULL;
//    }
//    rxq->next_to_clean = rx_id;
//    rxq->pkt_first_seg = first_seg;
//    rxq->pkt_last_seg = last_seg;
//    rxq->current_num = current_num;
//    hns_clean_rx_buffers(rxq, nb_hold);
//    return nb_rx;	
//    }
//    else{
//	struct hns_rx_queue *rxq = rx_queue;
//	uint8_t split_flags[32] = {0};   //收包对应的分片标记位数组，大小为同时收包的最大值，这里设定的是32
//	int rx_nb;
//	struct hns_adapter *hns;
//	
//	hns = rxq->hns;
//	
//	/* 收取nb_pkts个描述符 */
//	uint16_t nb_bufs = _recv_raw_pkts_vec(rxq, rx_pkts, nb_pkts,
//			split_flags);
//	
//	/* happy day case, full burst + no packets to be joined */   //最好情况，收的包全都不是分片的，直接成功
//	const uint64_t *split_fl64 = (uint64_t *)split_flags;
//
//	if (rxq->pkt_first_seg == NULL &&
//			split_fl64[0] == 0 && split_fl64[1] == 0 &&
//			split_fl64[2] == 0 && split_fl64[3] == 0)
//		return nb_bufs;
//		
//	/* reassemble any packets that need reassembly*/    //如果需要分片，那就看现在rxq的pkt_first_seg 是不是null，是的话在这次收的描述符中就找到第一个分片的mbuf
//	unsigned i = 0;
//
//	if (rxq->pkt_first_seg == NULL) {
//		/* find the first split flag, and only reassemble then*/
//		while (i < nb_bufs && !split_flags[i])
//			i++;
//		if (i == nb_bufs)
//			return nb_bufs;
//	}
//	rx_nb = i + reassemble_packets(rxq, &rx_pkts[i], nb_bufs - i,
//		&split_flags[i]);    //然后把分了片的组装起来
//	hns->stats.rx_pkts+=rx_nb;
//	
//	return rx_nb;
//    }
}


static uint16_t
eth_hns_recv_pkts_remain(void *rx_queue, struct rte_mbuf **rx_pkts, uint16_t nb_pkts)
{
    struct hns_rx_queue *rxq;       //RX queue 
    struct hnae_desc *rx_ring;      //RX ring (desc)
    struct hns_rx_entry *sw_ring;
    struct hns_rx_entry *rxe;
    struct hnae_desc *rxdp;         //pointer of the current desc
    struct rte_mbuf *first_seg;
    struct rte_mbuf *last_seg;
    struct hnae_desc rxd;           //current desc
    struct rte_mbuf *rxm;
    struct hns_adapter *hns;

    uint64_t dma_addr;
    uint16_t rx_id;
    uint16_t nb_hold;
	uint16_t nb_rx;
    uint16_t data_len;
    uint16_t pkt_len;
    int num;                   //num of desc in ring
    uint16_t bnum;
    uint32_t bnum_flag;
    uint16_t current_num;
    int length;

    nb_rx  =0;
    nb_hold = 0;
	rxq = rx_queue;
    hns = rxq->hns;
    rx_id = rxq->next_to_clean;
    rx_ring = rxq->rx_ring;
    first_seg = rxq->pkt_first_seg;
    last_seg = rxq->pkt_last_seg;
    current_num = rxq->current_num;
    sw_ring = rxq->sw_ring;
    //get num of packets in desc ring
    num = reg_read(hns->io_base, RCB_REG_FBDNUM, rxq->queue_id, 0);
    /*
    if(num < 16) {
        hns_clean_rx_buffers(rxq, nb_hold);
        return 0;
    }*/
    while(nb_rx < nb_pkts && nb_hold < num ){
next_desc:
        rxdp = &rx_ring[rx_id];
        rxd = *rxdp;
        rxe = &sw_ring[rx_id];

        nb_hold++;
        rx_id++;
        if(rx_id == rxq->nb_rx_desc) {
            rx_id = 0;
        }
        
        bnum_flag = rte_le_to_cpu_32(rxd.rx.ipoff_bnum_pid_flag);
        length = rte_le_to_cpu_16(rxd.rx.pkt_len); 
        get_v2rx_desc_bnum(bnum_flag, &bnum);
        
        if((rx_id & 0x3) == 0){
            rte_hns_prefetch(&rx_ring[rx_id]);
            rte_hns_prefetch(&sw_ring[rx_id]);
        }

        rte_hns_prefetch(sw_ring[rx_id].mbuf);
        rxm = rxe->mbuf;

        dma_addr = 
            rte_cpu_to_le_64(rte_mbuf_data_dma_addr_default(rxm));
        rxdp->addr = dma_addr;

        if(first_seg == NULL){
            //this is the first seg
            first_seg = rxm;
            first_seg-> nb_segs = bnum;
            first_seg->vlan_tci = 
                rte_le_to_cpu_16(hnae_get_field(rxd.rx.vlan_cfi_pri,HNS_RXD_VLANID_M, HNS_RXD_VLANID_S));
            if(length <= HNS_RX_HEAD_SIZE){
                if(unlikely(bnum != 1)){
                    goto pkt_err;
                }
            } else{
                if(unlikely(bnum >= (int)MAX_SKB_FRAGS)){
                    goto pkt_err;
                } 
            }
            current_num = 1;
        }else{
            //this is not the first seg
            last_seg->next = rxm;
        }
        
        /* Initialize the returned mbuf */
        pkt_len = (uint16_t) (rte_le_to_cpu_16(rxd.rx.pkt_len));
        data_len = (uint16_t) (rte_le_to_cpu_16(rxd.rx.size)); 
        rxm->data_off = RTE_PKTMBUF_HEADROOM;
        rxm->data_len = data_len;
        rxm->pkt_len = pkt_len;
        rxm->port = rxq->port_id;
        rxm->hash.rss = rxd.rx.rss_hash;
        
        hns->stats.rx_bytes += data_len;

        if(current_num < bnum) {
            last_seg = rxm;
            current_num++;
            goto next_desc;
        }
        hns->stats.rx_pkts++;
        bnum_flag = rte_le_to_cpu_32(rxd.rx.ipoff_bnum_pid_flag);
        
        rxm->next = NULL;
        //rte_packet_prefetch((char *)first_seg->buf_addr + first_seg->data_off);
        first_seg->packet_type = rxd_pkt_info_to_pkt_type(rxd.rx.ipoff_bnum_pid_flag);
        rx_pkts[nb_rx++] = first_seg;
        first_seg = NULL;
        continue;
pkt_err:
        rte_pktmbuf_free_seg(rxm);
        first_seg = NULL;
    }
    rxq->next_to_clean = rx_id;
    rxq->pkt_first_seg = first_seg;
    rxq->pkt_last_seg = last_seg;
    rxq->current_num = current_num;
    hns_clean_rx_buffers(rxq, nb_hold);
    return nb_rx;
}

/********************************************
 *
 *  Transmit unit
 *
 *******************************************/
static int
is_valid_clean_head(struct hns_tx_queue *txq, int h)
{
    int u = txq->next_to_use;
    int c = txq->next_to_clean;

    if(h > txq->nb_tx_desc)
        return 0;

    return u>c? (h>c && h<=u) : (h>c || h<=u);
}
    
static void
hns_tx_clean(struct hns_tx_queue *txq)
{
    unsigned long long value = 0;
    struct hns_adapter *hns;
    int head,qid;

    hns = txq->hns;
    qid = txq->queue_id;

    value = reg_read(hns->io_base, RCB_REG_HEAD, qid, 1);
   // if(hns->port == 5)
   // printf("head:%llu\n",value);
    //value = dsaf_reg_read(hns->uio_index, RCB_REG_HEAD, hns->cdev_fd,qid, 1);
    head = value;
    if(unlikely(!is_valid_clean_head(txq, head))) {
        PMD_TX_LOG(DEBUG, "head is not valid!");
        return;
    }
    //printf("next_to_clean:%d\n",head);
    txq->next_to_clean = head;
}


static void
hns_queue_xmit(struct hns_tx_queue *txq, int buf_num){
    struct hns_adapter *hns = txq->hns;
    //dsaf_reg_write(hns->uio_index, RCB_REG_TAIL, buf_num, hns->cdev_fd,txq->queue_id,1);
    //(void)reg_write;
    //(void)reg_read;
    reg_write(hns->io_base, RCB_REG_TAIL, txq->queue_id,1, buf_num);
}

static inline int
tx_ring_dist(struct hns_tx_queue *txq, int begin, int end)
{
    return (end - begin + txq->nb_tx_desc) % txq->nb_tx_desc;
}

static inline int
tx_ring_space(struct hns_tx_queue *txq){
    return txq->nb_tx_desc - 
        tx_ring_dist(txq, txq->next_to_clean, txq->next_to_use) - 1;
}

#define ETH_HLEN 14
#define VLAN_HLEN 4

#define BD_MAX_SEND_SIZE 8191


static void
fill_desc(struct hns_tx_queue* txq, struct rte_mbuf* rxm, int first,
         int buf_num, int port_id, int offset, int size, int frag_end)
{
    uint8_t rrcfv = 0;
    uint8_t tvsvsn = 0;
    uint8_t bn_pid = 0;
    uint8_t ip_offset = 0;
    uint16_t mss=0;
    uint16_t paylen=0;
    struct hnae_desc *tx_ring = txq->tx_ring;
    struct hnae_desc *desc = &tx_ring[txq->next_to_use];
    desc->addr = rte_mbuf_data_dma_addr(rxm)+offset;
    //desc->tx.send_size = rte_cpu_to_le_16((uint16_t)rxm->data_len);
    desc->tx.send_size = rte_cpu_to_le_16((uint16_t)size);
    hnae_set_bit(rrcfv, HNSV2_TXD_VLD_B,1);
    hnae_set_field(bn_pid, HNSV2_TXD_BUFNUM_M, 0, buf_num - 1);
    hnae_set_field(bn_pid, HNSV2_TXD_PORTID_M, HNSV2_TXD_PORTID_S, port_id);

    if(first == 1){
        ip_offset = ETH_HLEN;
        //if(flag & PKT_TX_VLAN_PKT)
        //    ip_offset += VLAN_HLEN;    
        if(rxm->packet_type & (RTE_PTYPE_L3_IPV4 | RTE_PTYPE_L3_IPV6)){
            hnae_set_bit(rrcfv, HNSV2_TXD_L4CS_B, 1);
            if(rxm->packet_type & RTE_PTYPE_L3_IPV6){
                hnae_set_bit(tvsvsn, HNSV2_TXD_IPV6_B, 1);
            }
            else{
                hnae_set_bit(rrcfv, HNSV2_TXD_L3CS_B, 1);
            }
            if(txq->hns->tso && (rxm->ol_flags & PKT_TX_TCP_SEG)){
                hnae_set_bit(tvsvsn, HNSV2_TXD_TSE_B, 1);
                //mss=BD_MAX_SEND_SIZE;//rxm->tso_segsz;
                desc->tx.paylen =rte_cpu_to_le_16((uint16_t)rxm->pkt_len) ;//rte_cpu_to_le_16(paylen);
           }
        }
        desc->tx.ip_offset = ip_offset;
        desc->tx.mss = rte_cpu_to_le_16(mss);
        desc->tx.paylen = rte_cpu_to_le_16(paylen);
        desc->tx.tse_vlan_snap_v6_sctp_nth = tvsvsn;
        desc->tx.l4_len = rxm->l4_len;
    }
    
    hnae_set_bit(rrcfv, HNSV2_TXD_FE_B, frag_end);
    desc->tx.bn_pid = bn_pid;
    desc->tx.ra_ri_cs_fe_vld = rrcfv;
    txq->next_to_use++;
    if(txq->next_to_use == txq->nb_tx_desc)
        txq->next_to_use = 0;
}

static int
fill_tso_desc(struct hns_tx_queue* txq, struct rte_mbuf* rxm, int first,
        int buf_num, int port_id, int offset, int size, int frag_end)
{
    int frag_buf_num;
    int sizeoflast;
    int k;
    (void)offset;
    frag_buf_num = (size + BD_MAX_SEND_SIZE - 1) / BD_MAX_SEND_SIZE;
    sizeoflast = size % BD_MAX_SEND_SIZE;
    sizeoflast = sizeoflast ? sizeoflast : BD_MAX_SEND_SIZE;
//    printf("in fill tso: size:%d,frag:%d\n",size,frag_buf_num);
    for(k = 0; k < frag_buf_num; k++){
        fill_desc(txq, rxm , first, buf_num, port_id, BD_MAX_SEND_SIZE * k,
                (k == frag_buf_num - 1) ? sizeoflast : BD_MAX_SEND_SIZE,
                frag_end && (k == frag_buf_num - 1) ? 1 : 0);
    }
    return frag_buf_num;
}

static void
hns_tx_queue_release_mbufs(struct hns_tx_queue *txq)
{
    unsigned i;
    for(i = 0; i < txq->nb_tx_desc; i++){
        if(txq->sw_ring[i].mbuf != NULL){
            rte_pktmbuf_free_seg(txq->sw_ring[i].mbuf);
            txq->sw_ring[i].mbuf = NULL;
        }
    }
}

/**
 * DPDK call back to release a TX queue
 *
 * @param txq
 *      TX queue pointer
 *
 */
void
eth_hns_tx_queue_release(void *queue) {
    if(queue != NULL){
        struct hns_tx_queue *txq = queue;
        hns_tx_queue_release_mbufs(txq);
        rte_free(txq->sw_ring);
        rte_free(txq);
    }
}
/**
 * DPDK callback to configure a TX queue
 *
 * @param dev
 *      Pointer to Ethernet device structure.
 * @param idx
 *      TX queue index.
 * @param nb_desc
 *      Number of descriptors to configure in queue.
 * @param socket
 *      NUMA socket on which memory must be allocated.
 * @param[in] conf
 *      Thresholds parameters.
 * @param mp
 *      Memory pool for buffer allocations.
 *
 * @return
 *      0 on success, negative errno value on failure.
 *
 */
static int
eth_hns_tx_queue_setup(struct rte_eth_dev *dev, uint16_t idx, uint16_t nb_desc,
        unsigned int socket, const struct rte_eth_txconf *conf)
{
    struct hns_adapter *hns = dev->data->dev_private;
    struct hns_tx_queue *txq;
    
    (void) socket;
    (void) conf;
    (void) nb_desc;
    if(dev->data->tx_queues[idx] != NULL){
        eth_hns_tx_queue_release(dev->data->tx_queues[idx]);
        dev->data->tx_queues[idx] = NULL;
    } 

    txq = rte_zmalloc("ethdev TX queue", sizeof(struct hns_tx_queue),
            RTE_CACHE_LINE_SIZE);
    if(txq == NULL)
        return -ENOMEM;
    txq->nb_tx_desc = hns->desc_num_per_txq;
    txq->queue_id = idx;
    txq->tx_ring = hns->tx_desc[idx];
    txq->nb_hold = 0;    
    txq->sw_ring = rte_zmalloc("txq->sw_ring",
                                sizeof(struct hns_tx_entry) * txq->nb_tx_desc,
                                RTE_CACHE_LINE_SIZE);
    if(txq->sw_ring == NULL){
        eth_hns_tx_queue_release(txq);
        return -ENOMEM;
    }

    PMD_INIT_LOG(DEBUG, "sw_ring=%p", txq->sw_ring);
    dev->data->tx_queues[idx] = txq;
    txq->next_to_use = 0;
    txq->next_to_clean = 0;
    txq->hns = hns;
    return 0;
}

/**
 *  DPDK callback for TX.
 *
 *  @param tx_queue
 *      Generic pointer to TX queue structure.
 *  @param[in] tx_pkts
 *      Packet to transmit.
 *  @param nb_pkts
 *      Number of packets in array
 *
 *  @return
 *      Number of packets successfully transmitted (<= nb_pkts)
 */
static uint16_t
eth_hns_xmit_pkts2(void *tx_queue, struct rte_mbuf **tx_pkts,
        uint16_t nb_pkts)
{
    struct hns_tx_queue *txq;
    struct rte_mbuf *tx_pkt;
    struct rte_mbuf *m_seg;
    struct rte_mbuf *temp;
    struct hns_adapter *hns;

    uint16_t tx_id;
    uint16_t nb_tx;
    uint16_t nb_buf;
    uint16_t port_id;
    uint32_t nb_hold;
    unsigned int i;
    txq = tx_queue;
    nb_hold = 0;
    hns = txq->hns;
    tx_id   = txq->next_to_use;
    (void) hns;
   // printf("next_to_use:%d,next_to_clean:%d\n",txq->next_to_use,txq->next_to_clean);
   // printf("nb_pkts:%d, space:%d, txq:%d,\n",nb_pkts,tx_ring_space(txq),txq->queue_id);
    for(nb_tx = 0; nb_tx < nb_pkts; nb_tx++) {
        tx_pkt = *tx_pkts++;

        nb_buf = tx_pkt->nb_segs;
        
        if(nb_buf > tx_ring_space(txq)){
            hns_tx_clean(txq);
     //       printf("txq:%d,result found at no ring space!\n",txq->queue_id);
     //       printf("nb_buf:%d, space:%d\n",nb_buf,tx_ring_space(txq));
            if(nb_tx == 0){
                return 0;
            }
            goto end_of_tx;
        }

        m_seg = tx_pkt;
        port_id = m_seg->port;
        nb_buf = m_seg->nb_segs;
        for(i = 0; i < nb_buf; i++){
            hns->stats.tx_bytes += m_seg->pkt_len;
            if(hns->tso){
                int frags = fill_tso_desc(txq, m_seg, (i==0), nb_buf, port_id,0,rte_cpu_to_le_16((uint16_t)m_seg->pkt_len),m_seg->next == NULL?1:0);
                nb_hold += (frags-1);
            }
            else{
                fill_desc(txq, m_seg, (i==0), nb_buf, port_id,0,rte_cpu_to_le_16((uint16_t)m_seg->pkt_len),m_seg->next == NULL?1:0);
            }
            temp = m_seg->next;
            rte_pktmbuf_free(m_seg);
            m_seg = temp;
            tx_id++;
            if((tx_id & 0x3) == 0)
                rte_hns_prefetch(m_seg);
            if(tx_id == txq->nb_tx_desc)
                tx_id = 0;
        }
        hns->stats.tx_pkts++;
        nb_hold += nb_buf;

        nb_tx++;
        if(!(nb_tx < nb_pkts))
        {
            break;
        }

        tx_pkt = *tx_pkts++;

        nb_buf = tx_pkt->nb_segs;
        
        if(nb_buf > tx_ring_space(txq)){
            hns_tx_clean(txq);
     //       printf("nb_buf:%d, space:%d\n",nb_buf,tx_ring_space(txq));
            if(nb_tx == 0){
                return 0;
            }
            goto end_of_tx;
        }

        m_seg = tx_pkt;
        port_id = m_seg->port;
        nb_buf = m_seg->nb_segs;
        for(i = 0; i < nb_buf; i++){
            hns->stats.tx_bytes += m_seg->pkt_len;
            if(hns->tso){
                int frags = fill_tso_desc(txq, m_seg, (i==0), nb_buf, port_id,0,rte_cpu_to_le_16((uint16_t)m_seg->pkt_len),m_seg->next == NULL?1:0);
                nb_hold += (frags-1);
            }
            else{
                fill_desc(txq, m_seg, (i==0), nb_buf, port_id,0,rte_cpu_to_le_16((uint16_t)m_seg->pkt_len),m_seg->next == NULL?1:0);
            }
            temp = m_seg->next;
            rte_pktmbuf_free(m_seg);
            m_seg = temp;
            tx_id++;
            if((tx_id & 0x3) == 0)
                rte_hns_prefetch(m_seg);
            if(tx_id == txq->nb_tx_desc)
                tx_id = 0;
        }
        hns->stats.tx_pkts++;
        nb_hold += nb_buf;
		 nb_tx++;
        if(!(nb_tx < nb_pkts))
        {
            break;
        }

        tx_pkt = *tx_pkts++;

        nb_buf = tx_pkt->nb_segs;
        
        if(nb_buf > tx_ring_space(txq)){
            hns_tx_clean(txq);
     //       printf("txq:%d,result found at no ring space!\n",txq->queue_id);
     //       printf("nb_buf:%d, space:%d\n",nb_buf,tx_ring_space(txq));
            if(nb_tx == 0){
                return 0;
            }
            goto end_of_tx;
        }

        m_seg = tx_pkt;
        port_id = m_seg->port;
        nb_buf = m_seg->nb_segs;
        for(i = 0; i < nb_buf; i++){
            hns->stats.tx_bytes += m_seg->pkt_len;
            if(hns->tso){
                int frags = fill_tso_desc(txq, m_seg, (i==0), nb_buf, port_id,0,rte_cpu_to_le_16((uint16_t)m_seg->pkt_len),m_seg->next == NULL?1:0);
                nb_hold += (frags-1);
            }
            else{
                fill_desc(txq, m_seg, (i==0), nb_buf, port_id,0,rte_cpu_to_le_16((uint16_t)m_seg->pkt_len),m_seg->next == NULL?1:0);
            }
            temp = m_seg->next;
            rte_pktmbuf_free(m_seg);
            m_seg = temp;
            tx_id++;
            if((tx_id & 0x3) == 0)
                rte_hns_prefetch(m_seg);
            if(tx_id == txq->nb_tx_desc)
                tx_id = 0;
        }
        hns->stats.tx_pkts++;
        nb_hold += nb_buf;
		
		 nb_tx++;
        if(!(nb_tx < nb_pkts))
        {
            break;
        }

        tx_pkt = *tx_pkts++;

        nb_buf = tx_pkt->nb_segs;
        
        if(nb_buf > tx_ring_space(txq)){
            hns_tx_clean(txq);
     //       printf("txq:%d,result found at no ring space!\n",txq->queue_id);
     //       printf("nb_buf:%d, space:%d\n",nb_buf,tx_ring_space(txq));
            if(nb_tx == 0){
                return 0;
            }
            goto end_of_tx;
        }

        m_seg = tx_pkt;
        port_id = m_seg->port;
        nb_buf = m_seg->nb_segs;
        for(i = 0; i < nb_buf; i++){
            hns->stats.tx_bytes += m_seg->pkt_len;
            if(hns->tso){
                int frags = fill_tso_desc(txq, m_seg, (i==0), nb_buf, port_id,0,rte_cpu_to_le_16((uint16_t)m_seg->pkt_len),m_seg->next == NULL?1:0);
                nb_hold += (frags-1);
            }
            else{
                fill_desc(txq, m_seg, (i==0), nb_buf, port_id,0,rte_cpu_to_le_16((uint16_t)m_seg->pkt_len),m_seg->next == NULL?1:0);
            }
            temp = m_seg->next;
            rte_pktmbuf_free(m_seg);
            m_seg = temp;
            tx_id++;
            if((tx_id & 0x3) == 0)
                rte_hns_prefetch(m_seg);
            if(tx_id == txq->nb_tx_desc)
                tx_id = 0;
        }
        hns->stats.tx_pkts++;
        nb_hold += nb_buf;
    }
end_of_tx:
    rte_wmb();
    hns_queue_xmit(txq, (unsigned long long)nb_hold);
    //printf("xmit pkt:%d\n",nb_hold);
    hns_tx_clean(txq);
    //printf("nb_tx:%d\n",nb_tx);
    return nb_tx;
//    struct hns_tx_queue *txq;
//    struct rte_mbuf *tx_pkt;
//    struct rte_mbuf *m_seg;
//    struct rte_mbuf *temp;
//    struct hns_adapter *hns;
//
//    uint16_t tx_id;
//    uint16_t nb_tx;
//    uint16_t nb_buf;
//    uint16_t port_id;
//    uint32_t nb_hold;
//    unsigned int i;
//    txq = tx_queue;
//    nb_hold = 0;
//    hns = txq->hns;
//    tx_id   = txq->next_to_use;
//    (void) hns;
//   // printf("next_to_use:%d,next_to_clean:%d\n",txq->next_to_use,txq->next_to_clean);
//   // printf("nb_pkts:%d, space:%d, txq:%d,\n",nb_pkts,tx_ring_space(txq),txq->queue_id);
//    for(nb_tx = 0; nb_tx < nb_pkts; nb_tx++) {
//        tx_pkt = *tx_pkts++;
//
//        nb_buf = tx_pkt->nb_segs;
//        
//        if(nb_buf > tx_ring_space(txq)){
//            hns_tx_clean(txq);
//			//if(nb_buf > tx_ring_space(txq)){
//     //       if(hns->port == 5)
//     //       printf("port:%d,result found at no ring space,nb_buf:%d!\n",hns->port,nb_buf);
//     //       printf("nb_buf:%d, space:%d\n",nb_buf,tx_ring_space(txq));
//            if(nb_tx == 0){
//                return 0;
//            }
//            goto end_of_tx;
//			//}
//        }
//
//        m_seg = tx_pkt;
//        port_id = m_seg->port;
//        nb_buf = m_seg->nb_segs;
//        for(i = 0; i < nb_buf; i++){
//            hns->stats.tx_bytes += m_seg->pkt_len;
//            if(hns->tso){
//                int frags = fill_tso_desc(txq, m_seg, (i==0), nb_buf, port_id,0,rte_cpu_to_le_16((uint16_t)m_seg->pkt_len),m_seg->next == NULL?1:0);
//                nb_hold += (frags-1);
//            }
//            else{
//                fill_desc(txq, m_seg, (i==0), nb_buf, port_id,0,rte_cpu_to_le_16((uint16_t)m_seg->pkt_len),m_seg->next == NULL?1:0);
//            }
//            temp = m_seg->next;
//            rte_pktmbuf_free(m_seg);
//            m_seg = temp;
//            tx_id++;
//            if((tx_id & 0x3) == 0)
//                rte_hns_prefetch(m_seg);
//            if(tx_id == txq->nb_tx_desc)
//                tx_id = 0;
//        }
//        hns->stats.tx_pkts++;
//        nb_hold += nb_buf;
//    }
//end_of_tx:
//    rte_wmb();
//    hns_queue_xmit(txq, (unsigned long long)nb_hold);
//    //printf("xmit pkt:%d\n",nb_hold);
//    hns_tx_clean(txq);
//    //printf("nb_tx:%d\n",nb_tx);
//    return nb_tx;
}

static void
fill_desc_neon(struct hns_tx_queue* txq, struct rte_mbuf** rxm, int* first,
         uint8_t* buf_num, uint8_t* port_id, int* offset, uint32_t* size, int* frag_end,int count)
{
	uint8_t rrcfv_temp1[2] = {0};
    uint8_t tvsvsn_temp1[2] = {0};
    uint8_t rrcfv_temp2[4] ={0};
    uint8_t rrcfv_temp3[4] ={0};
    uint8_t rrcfv_temp4[4] ={0};
    uint8_t tvsvsn_temp2[4]={0};
    uint8_t tvsvsn_temp3[4]={0};
    uint8_t ip_offset_temp[4]={0};
    uint8_t rrcfv_fragend=0x00,rrcfv_temp=0x00;
    uint8x16_t rrcfv, tvsvsn, bn_pid, ip_offset;
    uint32x4_t s;
    uint8x16_t mask,val,data_tmp1,data_tmp2;
    uint16x8_t data_tmp3;
    uint32x4x2_t data_tmp4;
    //uint64x2x2_t data_tmp5,data_tmp6;
    uint64_t addr[4];
    uint16_t mss=0;
    uint64x2_t addr_tmp,data_tmp;
    uint64_t flag[4];
    int i=0;
    for(i=0;i<count;i++){
    	flag[i] = rxm[i]->ol_flags;
    }
    struct hnae_desc *tx_ring = txq->tx_ring;
    struct hnae_desc *desc[4];
    if((txq->next_to_use+3) >= txq->nb_tx_desc)
        txq->next_to_use = 0;
    for(i=0;i<count;i++){
    	desc[i] = &tx_ring[(txq->next_to_use)++];
		if(txq->next_to_use == txq->nb_tx_desc)
			txq->next_to_use = 0;
    }

    s=vld1q_u32(size);
    s=vshlq_n_u32 (s,16);
    for(i=0;i<count;i++){
    	addr[i]= rte_mbuf_data_dma_addr(rxm[i])+offset[i];
    }

    hnae_set_bit(rrcfv_temp , HNSV2_TXD_VLD_B,1);
    rrcfv=vld1q_dup_u8(&rrcfv_temp);

    bn_pid=vdupq_n_u8((uint8_t) 0);
    mask=vdupq_n_u8((uint8_t) HNSV2_TXD_BUFNUM_M);
    bn_pid=vandq_u8(bn_pid,vmvnq_u8(mask));
    val=vld1q_u8(buf_num);
    val=vsubq_u8 (val,vdupq_n_u8((uint8_t) 1));
    val=vandq_u8 (val,mask);
    bn_pid=vorrq_u8(bn_pid,val);

    bn_pid=vdupq_n_u8((uint8_t) 0);
    mask=vdupq_n_u8((uint8_t) HNSV2_TXD_PORTID_M);
    bn_pid=vandq_u8(bn_pid,vmvnq_u8(mask));
    val=vld1q_u8(port_id);
    val=vshlq_n_u8 (val,HNSV2_TXD_PORTID_S);
    val=vandq_u8 (val,mask);
    bn_pid=vorrq_u8(bn_pid,val);
    
    for(i=0;i<count;i++){
    	if(first[i] == 1){
        	ip_offset_temp[i] = ETH_HLEN;
        	if(flag[i] & PKT_TX_VLAN_PKT)
            	ip_offset_temp[i] += VLAN_HLEN;    

        	if(rxm[i]->packet_type & (RTE_PTYPE_L3_IPV4 | RTE_PTYPE_L3_IPV6)){
  //        	  printf("ipv4 or ipv6\n");
        		if(!rrcfv_temp1[0]){
            		hnae_set_bit(rrcfv_temp1[0], HNSV2_TXD_L4CS_B, 1);
            	}
                rrcfv_temp2[i]=rrcfv_temp1[0];
                //rrcfv=vld1q_lane_u8 (&rrcfv_temp1[0], rrcfv,   i);
                //wait 

            	if(rxm[i]->packet_type & RTE_PTYPE_L3_IPV6){
            		if(!tvsvsn_temp1[0]){
                		hnae_set_bit(tvsvsn_temp1[0], HNSV2_TXD_IPV6_B, 1);
                    }
                    tvsvsn_temp2[i]=tvsvsn_temp1[0];
                    //tvsvsn=vld1q_lane_u8 (&tvsvsn_temp1[0], tvsvsn,   i);
                    //wait
            	}
            	else{
            		if(!rrcfv_temp1[1]){
                		hnae_set_bit(rrcfv_temp1[1], HNSV2_TXD_L3CS_B, 1);
                	}
                	rrcfv_temp3[i]=rrcfv_temp1[1];
                    //rrcfv=vld1q_lane_u8 (&rrcfv_temp1[1], rrcfv,   i);
                    //wait
            	}

            	//if(rxm->ol_flags & PKT_TX_TCP_SEG){
            	if(txq->hns->tso && (flag[i] & PKT_TX_TCP_SEG)){
            		if(!tvsvsn_temp1[1]){
                		hnae_set_bit(tvsvsn, HNSV2_TXD_TSE_B, 1);
                	}
                	tvsvsn_temp3[i]=tvsvsn_temp1[1];
                    //tvsvsn=vld1q_lane_u8 (&tvsvsn_temp1[1], tvsvsn,   i);
                	//wait
                	mss=BD_MAX_SEND_SIZE;//rxm->tso_segsz;
                	desc[i]->tx.paylen =rte_cpu_to_le_16((uint16_t)rxm[i]->pkt_len) ;//rte_cpu_to_le_16(paylen);
           		}
        	}
 //       	printf("ip_offset:%d, size:%d\n",ip_offset,size);
        	desc[i]->tx.mss = rte_cpu_to_le_16(mss);
        	desc[i]->tx.l4_len = rxm[i]->l4_len;
     	}
    }

    for(i=0;i<count;i++){
    	if(frag_end[i]){
    		if(!rrcfv_fragend){
    			hnae_set_bit(rrcfv_fragend, HNSV2_TXD_FE_B, 1); 
    		}
    		rrcfv_temp4[i]=rrcfv_fragend;
    		//rrcfv=vld1q_lane_u8 (&frag_end, rrcfv,   i);
    		//wait
    	}
    }
    

    rrcfv=vorrq_u8(vld1q_u8 (rrcfv_temp2),rrcfv);
    rrcfv=vorrq_u8(vld1q_u8 (rrcfv_temp3),rrcfv);
    rrcfv=vorrq_u8(vld1q_u8 (rrcfv_temp4),rrcfv);
    tvsvsn=vld1q_u8 (tvsvsn_temp2);
    tvsvsn=vorrq_u8(vld1q_u8 (tvsvsn_temp3),tvsvsn);
    ip_offset=vld1q_u8 (ip_offset_temp);
    

    data_tmp1=vzipq_u8(bn_pid,rrcfv).val[0];
    data_tmp2=vzipq_u8(ip_offset,tvsvsn).val[0];
    data_tmp3=vzipq_u16(vreinterpretq_u16_u8(data_tmp1),
				       vreinterpretq_u16_u8(data_tmp2)).val[0];
    data_tmp4=vzipq_u32(s,vreinterpretq_u32_u16(data_tmp3));
    //data_tmp5=vzipq_u64(addr1,vreinterpretq_u64_u32(data_tmp4.val[0]));
    //data_tmp6=vzipq_u64(addr2,vreinterpretq_u64_u32(data_tmp4.val[1]));

    //finally put the data into the desc
    if(count>0){
    	addr_tmp=vld1q_u64(addr);
    	data_tmp=vsetq_lane_u64 (vgetq_lane_u64 (vreinterpretq_u64_u32(data_tmp4.val[0]) ,0),addr_tmp, 1);
    	vst1q_u64((void *)desc[0],data_tmp);
    	count=count-1;
    	if(count>0){
    		data_tmp=vld1q_lane_u64 (addr+1, vreinterpretq_u64_u32(data_tmp4.val[0]) ,0);
			vst1q_u64((void *)desc[1],data_tmp);
			count=count-1;
			if(count>0){
				addr_tmp=vld1q_u64(addr+2);
    			data_tmp=vsetq_lane_u64 (vgetq_lane_u64 (vreinterpretq_u64_u32(data_tmp4.val[0]) ,0),addr_tmp, 1);
    			vst1q_u64((void *)desc[2],data_tmp);
    			count=count-1;
				if(count>0){
    				data_tmp=vld1q_lane_u64 (addr+3, vreinterpretq_u64_u32(data_tmp4.val[1]) ,0);
					vst1q_u64((void *)desc[3],data_tmp);
				}
			}
		}
	}
}




static uint16_t
eth_hns_xmit_pkts3(void *tx_queue, struct rte_mbuf **tx_pkts,
        uint16_t nb_pkts)
{
    struct hns_tx_queue *txq;
    struct rte_mbuf *tx_pkt[4];
    struct rte_mbuf *m_seg;
    struct rte_mbuf *temp;
    struct hns_adapter *hns;

    uint16_t tx_id;
    uint16_t nb_tx;
    uint16_t nb_buf;
    uint16_t port_id;
    uint32_t nb_hold;
    uint8_t buf_num[4],port_ids[4];
    uint32_t sizes[4];
    int offsets[4]={0,0,0,0},frag_end[4]={0,0,0,0},first[4]={0,0,0,0};
    unsigned int i;
    txq = tx_queue;
    nb_hold = 0;
    hns = txq->hns;
    tx_id   = txq->next_to_use;
    (void) hns;
    int count=0;
    printf("next_to_use:%d,next_to_clean:%d\n",txq->next_to_use,txq->next_to_clean);
    printf("nb_pkts:%d, space:%d, txq:%d,\n",nb_pkts,tx_ring_space(txq),txq->queue_id);
    for(nb_tx = 0; nb_tx < nb_pkts; ) {
    	count=0;
    	for(i=0;i<4;i++){
        	tx_pkt[i] = *tx_pkts++;
        	m_seg=*tx_pkts;
        	nb_buf = m_seg->nb_segs;
        	if(nb_buf==1){
                 count++;
                 hns->stats.tx_bytes += m_seg->pkt_len;
                 buf_num[i]=m_seg->nb_segs;
                 port_ids[i]=m_seg->port;
                 first[i]=1;
                 sizes[i]=rte_cpu_to_le_32((uint32_t)m_seg->pkt_len);
                 frag_end[i]=1;
                 tx_id++;
            	 if((tx_id & 0x3) == 0)
                 rte_hns_prefetch(m_seg);
            	 if(tx_id == txq->nb_tx_desc)
                	tx_id = 0;
                 nb_tx++;
                 if(nb_tx >= nb_pkts){
                 	break;
                 }
        	}
        	else{

        		if(nb_buf > tx_ring_space(txq)){
            printf("txq:%d,result found at no ring space!\n",txq->queue_id);
            printf("nb_buf:%d, space:%d\n",nb_buf,tx_ring_space(txq));
            		if(nb_tx == 0){
                		return 0;
            		}
            		goto end_of_tx;
	        	}

        		port_id = m_seg->port;
        		nb_buf = m_seg->nb_segs;
        		for(i = 0; i < nb_buf; i++){
            		hns->stats.tx_bytes += m_seg->pkt_len;
            		if(hns->tso){
                		int frags = fill_tso_desc(txq, m_seg, (i==0), nb_buf, port_id,0,rte_cpu_to_le_16((uint16_t)m_seg->pkt_len),m_seg->next == NULL?1:0);
                		nb_hold += (frags-1);
            		}
            		else{
                		fill_desc(txq, m_seg, (i==0), nb_buf, port_id,0,rte_cpu_to_le_16((uint16_t)m_seg->pkt_len),m_seg->next == NULL?1:0);
            		}
            		temp = m_seg->next;
            		rte_pktmbuf_free(m_seg);
            		m_seg = temp;
            		tx_id++;
            		if((tx_id & 0x3) == 0)
                	rte_hns_prefetch(m_seg);
            		if(tx_id == txq->nb_tx_desc)
                	tx_id = 0;
        		}
        		hns->stats.tx_pkts++;
        		nb_hold += nb_buf;
        		nb_tx++;
        		break;
  				}

        }
        if(count > tx_ring_space(txq)){
            printf("txq:%d,result found at no ring space!\n",txq->queue_id);
            printf("nb_buf:%d, space:%d\n",nb_buf,tx_ring_space(txq));
            		if(nb_tx == 0){
                		return 0;
            		}
            		goto end_of_tx;
	        	}
        if(count==1){
        			fill_desc(txq, tx_pkt[0], 1, buf_num[0], port_ids[0],0,rte_cpu_to_le_16((uint16_t)tx_pkt[i-1]->pkt_len),1);
        			hns->stats.tx_pkts+=1;
        			nb_hold += 1;
        		}
        else if(count > 1){
			        printf("count = %d\n", count);
        			fill_desc_neon(txq,tx_pkt,first,buf_num,port_ids,offsets,sizes,frag_end,count);
        			hns->stats.tx_pkts+=count;
        			nb_hold += count;
        		}
        }
       
end_of_tx:
    rte_wmb();
    hns_queue_xmit(txq, (unsigned long long)nb_hold);
    hns_tx_clean(txq);
        printf("nb_tx:%d\n",nb_tx);
    return nb_tx;
}

static uint16_t
eth_hns_xmit_pkts(void *tx_queue, struct rte_mbuf **tx_pkts,
        uint16_t nb_pkts)
{
    struct hns_tx_queue *txq;
    struct rte_mbuf *tx_pkt;
    struct rte_mbuf *m_seg;
    struct rte_mbuf *temp;
    struct hns_adapter *hns;

    uint16_t tx_id;
    uint16_t nb_tx;
    uint16_t nb_buf;
    uint16_t port_id;
    uint32_t nb_hold;
    unsigned int i;
    txq = tx_queue;
    nb_hold = 0;
    hns = txq->hns;
    tx_id   = txq->next_to_use;
    (void) hns;
    for(nb_tx = 0; nb_tx < nb_pkts; nb_tx++) {
        tx_pkt = *tx_pkts++;

        nb_buf = tx_pkt->nb_segs;
        
        if(nb_buf > tx_ring_space(txq)){
            hns_tx_clean(txq);
            if(nb_tx == 0){
                return 0;
            }
            goto end_of_tx;
        }

        m_seg = tx_pkt;
        port_id = m_seg->port;
        nb_buf = m_seg->nb_segs;
        for(i = 0; i < nb_buf; i++){
            hns->stats.tx_bytes += m_seg->pkt_len;
            if(hns->tso){
                int frags = fill_tso_desc(txq, m_seg, (i==0), nb_buf, port_id,0,rte_cpu_to_le_16((uint16_t)m_seg->pkt_len),m_seg->next == NULL?1:0);
                nb_hold += (frags-1);
            }
            else{
                fill_desc(txq, m_seg, (i==0), nb_buf, port_id,0,rte_cpu_to_le_16((uint16_t)m_seg->pkt_len),m_seg->next == NULL?1:0);
            }
            temp = m_seg->next;
            rte_pktmbuf_free(m_seg);
            m_seg = temp;
            tx_id++;
            if((tx_id & 0x3) == 0)
                rte_hns_prefetch(m_seg);
            if(tx_id == txq->nb_tx_desc)
                tx_id = 0;
        }
        hns->stats.tx_pkts++;
        nb_hold += nb_buf;
    }
end_of_tx:
    rte_wmb();
    hns_queue_xmit(txq, (unsigned long long)nb_hold);
    hns_tx_clean(txq);
    return nb_tx;
}

static uint16_t
eth_hns_xmit_pkts_remain(void *tx_queue, struct rte_mbuf **tx_pkts,
        uint16_t nb_pkts)
{
    struct hns_tx_queue *txq;
    struct rte_mbuf *tx_pkt;
    struct rte_mbuf *m_seg;
    struct rte_mbuf *temp;
    struct hns_adapter *hns;

    uint16_t tx_id;
    uint16_t nb_tx;
    uint16_t nb_buf;
    uint16_t port_id;
    uint32_t nb_hold;
    unsigned int i;
    txq = tx_queue;
    nb_hold = 0;
    hns = txq->hns;
    tx_id   = txq->next_to_use;
    (void) hns;
    //printf("next_to_use:%d,next_to_clean:%d\n",txq->next_to_use,txq->next_to_clean);
    //printf("nb_pkts:%d, space:%d, txq:%d,\n",nb_pkts,tx_ring_space(txq),txq->queue_id);
    for(nb_tx = 0; nb_tx < nb_pkts; nb_tx++) {
        tx_pkt = *tx_pkts++;

        nb_buf = tx_pkt->nb_segs;
        
        if(nb_buf > tx_ring_space(txq)){
            //printf("txq:%d,result found at no ring space!\n",txq->queue_id);
            //printf("nb_buf:%d, space:%d\n",nb_buf,tx_ring_space(txq));
            if(nb_tx == 0){
                return 0;
            }
            goto end_of_tx;
        }

        m_seg = tx_pkt;
        port_id = m_seg->port;
        nb_buf = m_seg->nb_segs;
        for(i = 0; i < nb_buf; i++){
            hns->stats.tx_bytes += m_seg->pkt_len;
            if(hns->tso){
                int frags = fill_tso_desc(txq, m_seg, (i==0), nb_buf, port_id,0,rte_cpu_to_le_16((uint16_t)m_seg->pkt_len),m_seg->next == NULL?1:0);
                nb_hold += (frags-1);
            }
            else{
                fill_desc(txq, m_seg, (i==0), nb_buf, port_id,0,rte_cpu_to_le_16((uint16_t)m_seg->pkt_len),m_seg->next == NULL?1:0);
            }
            temp = m_seg->next;
            m_seg = temp;
            tx_id++;
            if((tx_id & 0x3) == 0)
                rte_hns_prefetch(m_seg);
            if(tx_id == txq->nb_tx_desc)
                tx_id = 0;
        }
        hns->stats.tx_pkts++;
        nb_hold += nb_buf;
    }
end_of_tx:
    rte_wmb();
    hns_queue_xmit(txq, (unsigned long long)nb_hold);
    hns_tx_clean(txq);
        //printf("nb_tx:%d\n",nb_tx);
    return nb_tx;
}

static const struct eth_dev_ops eth_hns_ops = {
    .dev_start          = eth_hns_start,
    .dev_stop           = eth_hns_stop,
    .dev_close          = eth_hns_close,
    .mtu_set            = eth_hns_set_mtu,
    .stats_get          = eth_hns_stats_get,
    .stats_reset        = eth_hns_stats_reset,
    .dev_infos_get      = eth_hns_dev_infos_get,
    .rx_queue_setup     = eth_hns_rx_queue_setup,
    .tx_queue_setup     = eth_hns_tx_queue_setup,
    .rx_queue_release   = eth_hns_rx_queue_release,
    .tx_queue_release   = eth_hns_tx_queue_release,
    .promiscuous_enable = eth_hns_promisc_enable,
    .promiscuous_disable = eth_hns_promisc_disable,
    .tso_enable = eth_hns_tso_enable,
    .tso_disable = eth_hns_tso_disable,
    .allmulticast_enable = eth_hns_allmulticast_enable,
    .dev_set_link_up = eth_hns_configure,
    .dev_set_link_down = eth_hns_configure,
    .dev_configure      = eth_hns_configure,
    .mac_addr_set       = eth_hns_mac_addr_set,
    .link_update        = eth_hns_link_update,
    .reta_update        = eth_hns_reta_update,
    .reta_query         = eth_hns_reta_query,
	.dev_supported_ptypes_get = eth_hns_supported_ptypes_get,
};

static int
eth_hns_dev_init (struct rte_eth_dev *dev){
    struct hns_adapter *hns = dev->data->dev_private;
    struct hns_uio_ioctrl_para args;
	struct rte_platform_device *pdev = HNS_DEV_TO_PLATFORM(dev);
    int uio_index = 
        (int)pdev->mem_resource[3].phys_addr;
    int fd, i;
    unsigned int tx_desc, rx_desc;
    unsigned int desc_size = sizeof(struct hnae_desc);
    unsigned int total_tx_desc_len = 
        (unsigned int)pdev->mem_resource[1].len;
    unsigned int total_rx_desc_len = 
        (unsigned int)pdev->mem_resource[2].len;

    //set dev_ops
    dev->dev_ops = &eth_hns_ops;

    
    //set io_base
    hns->io_base = (void *)pdev->mem_resource[0].addr;

    //set uio_index
    hns->uio_index = uio_index;
    
    //set cdev fd
    fd = open("/dev/nic_uio", O_RDWR);
    if (fd < 0){
        PMD_INIT_LOG(ERR, "Cannot open dev nic_uio");
        return -EIO;
    }
    hns->cdev_fd = fd;
 
    hns->port = dev->data->port_id;
    //set queue num
    args.index = uio_index;
    if(ioctl(hns->cdev_fd, HNS_UIO_IOCTL_QNUM, &args) < 0) {
        PMD_INIT_LOG(ERR, "Get queue num failed!");
        return -EIO;
    }
    hns->q_num = (unsigned int)args.value;
    //set desc pointer
    tx_desc = total_tx_desc_len/(hns->q_num * desc_size);
    rx_desc = total_rx_desc_len/(hns->q_num * desc_size);
    hns->desc_num_per_txq = tx_desc;
    hns->desc_num_per_rxq = rx_desc;
    
    tx_desc *= desc_size;
    rx_desc *= desc_size;
    for(i = 0; i < (int)hns->q_num; i++){
        hns->tx_desc[i] = (void *)((char *)pdev->mem_resource[1].addr + i*tx_desc);
        
        hns->rx_desc[i] = (void *)((char *)pdev->mem_resource[2].addr + i*rx_desc);
    }

    //set vf id
    if(ioctl(hns->cdev_fd, HNS_UIO_IOCTL_VF_ID, &args) < 0) {
        PMD_INIT_LOG(ERR, "Get vf id failed!");
        return -EIO;
    }
    hns->vf_id = (unsigned int)args.value;

    //set vf max
    if(ioctl(hns->cdev_fd, HNS_UIO_IOCTL_VF_MAX, &args) < 0) {
        PMD_INIT_LOG(ERR, "Get vf max failed!");
        return -EIO;
    }
    hns->vf_sum = (unsigned int)args.value;

    //set send/recv function
    dev->tx_pkt_burst = eth_hns_xmit_pkts;
    dev->rx_pkt_burst = eth_hns_recv_pkts;

    (void) eth_hns_xmit_pkts2;
	(void) eth_hns_xmit_pkts3;
    dev->tx_pkt_burst_remain = eth_hns_xmit_pkts_remain;
    dev->rx_pkt_burst_remain = eth_hns_recv_pkts_remain;

	/* Allocate memory for storing MAC addresses */
	dev->data->mac_addrs = rte_zmalloc("hns-mac",ETHER_ADDR_LEN, 0);
	if (dev->data->mac_addrs == NULL) {
		PMD_INIT_LOG(ERR, "Failed to allocate %d bytes needed to "
						"store MAC addresses",ETHER_ADDR_LEN);
		return -ENOMEM;
	}
    if(ioctl(fd, HNS_UIO_IOCTL_INIT_MAC, &args) < 0) {
        PMD_INIT_LOG(ERR, "mac init failed!\n");
        return -EINVAL;
    }
	ether_addr_copy((struct ether_addr *)args.data, &dev->data->mac_addrs[0]);
    dev->data->nb_rx_queues = 16;
    dev->data->nb_tx_queues = 16;
    return 0;
}

static int
eth_hns_dev_uninit (struct rte_eth_dev *dev){
    struct hns_adapter *hns = dev->data->dev_private;
    struct rte_platform_device *platform_dev;
    
    if (hns->stopped == 0)
        eth_hns_close(dev);

    platform_dev = HNS_DEV_TO_PLATFORM(dev);
    if(platform_dev->intr_handle.intr_vec){
        rte_free(platform_dev->intr_handle.intr_vec);
        platform_dev->intr_handle.intr_vec = NULL;
    }
    dev->dev_ops = NULL;
    dev->rx_pkt_burst = NULL;
    dev->tx_pkt_burst = NULL;
    close(hns->cdev_fd);

    return 0;
}


static int eth_hns_platform_probe(struct rte_platform_driver *platform_drv __rte_unused,
	struct rte_platform_device *platform_dev)
{
	return rte_eth_dev_platform_generic_probe(platform_dev,
		sizeof(struct hns_adapter), eth_hns_dev_init);
}

static int eth_hns_platform_remove(struct rte_platform_device *platform_dev)
{
	return rte_eth_dev_platform_generic_remove(platform_dev, eth_hns_dev_uninit);
}

/*
 * virtual function driver struct
 */
static struct rte_platform_driver rte_hns_pmd = {
	.id_table = platform_id_hns_map,
	.drv_flags = RTE_PLATFORM_DRV_NEED_MAPPING | RTE_PLATFORM_DRV_INTR_LSC,
	.probe = eth_hns_platform_probe,
	.remove = eth_hns_platform_remove,
};




RTE_PMD_REGISTER_PLATFORM(net_hns, rte_hns_pmd);
/*PMD_REGISTER_DRIVER(rte_hnsvf_driver, hnsvf);*/

