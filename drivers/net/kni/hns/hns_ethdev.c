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

/*
 * The set of Platform devices this driver supports
 */
static const struct rte_platform_id platform_id_hns_map[] = {
    {.name = "HISI00C2:03"},
    {.name = "HISI00C2:02"},
    {0},
};

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


/**
 * DPDK callback to start the device.
 *
 */
static int
eth_hns_start(struct rte_eth_dev *dev)
{
    struct hns_adapter *hns = dev->data->dev_private;
    struct hns_uio_ioctrl_para args;
    int uio_index = hns->uio_index;
    args.index = uio_index;
//    if(ioctl(hns->cdev_fd, HNS_UIO_IOCTL_MAC, &args) < 0) {
//        PMD_INIT_LOG(ERR, "Set mac addr failed!");
//        return -EINVAL;
//    }
    if(ioctl(hns->cdev_fd, HNS_UIO_IOCTL_UP, &args) < 0) {
        PMD_INIT_LOG(ERR, "Open dev failed!");
        return -EINVAL;
    }
    printf("Open dev success!\n");
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
    printf("get link success!\n");
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
    //dsaf_reg_write(hns->uio_index, RCB_REG_HEAD, cleaned_count, hns->cdev_fd, qid,0);
    reg_write(hns->io_base, RCB_REG_HEAD, qid,0,cleaned_count);
//    if(qid == (int)hns->q_num-1){
//        write_all_rxhead(hns);
//    }

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
        printf("no space for rx_queue\n");
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
        printf("no space for sw_ring\n");
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
static uint16_t
eth_hns_recv_pkts(void *rx_queue, struct rte_mbuf **rx_pkts, uint16_t nb_pkts)
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
    //num = dsaf_reg_read(hns->uio_index, RCB_REG_FBDNUM, hns->cdev_fd,rxq->queue_id, 0);
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

//#ifdef OPTIMIZATION
//        if(rte_ring_dequeue(rxq->cache_ring, 
//                    nmb_buf)<0){
//            PMD_RX_LOG(DEBUG, "RX mbuf alloc failed port_id=%u "
//                        "queue_id=%u", (unsigned) rxq->port_id,
//                        (unsigned) rxq->queue_id);
//            rte_eth_devices[rxq->port_id].data->rx_mbuf_alloc_failed++;
//            break;
//        }
//        nmb = nmb_buf[0];
//#else
        nmb = rte_mbuf_raw_alloc(rxq->mb_pool);
        if (nmb == NULL){
            PMD_RX_LOG(DEBUG, "RX mbuf alloc failed port_id=%u "
                        "queue_id=%u", (unsigned) rxq->port_id,
                        (unsigned) rxq->queue_id);
            rte_eth_devices[rxq->port_id].data->rx_mbuf_alloc_failed++;
            break;
        }
//#endif
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
        rxe->mbuf = nmb;

        dma_addr = 
            //rte_cpu_to_le_64(rte_mbuf_data_dma_addr_default(rxm));
            rte_cpu_to_le_64(rte_mbuf_data_dma_addr_default(nmb));
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
    //value = dsaf_reg_read(hns->uio_index, RCB_REG_HEAD, hns->cdev_fd,qid, 1);
    rte_rmb();
    head = value;
    if(unlikely(!is_valid_clean_head(txq, head))) {
        PMD_TX_LOG(DEBUG, "head is not valid!");
        return;
    }

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
//    uint16_t paylen = 0;
    uint16_t mss=0;
    uint64_t flag = rxm->ol_flags;
    struct hnae_desc *tx_ring = txq->tx_ring;
    struct hnae_desc *desc = &tx_ring[txq->next_to_use];
    /*if(tso_flag){
        int frag_buf_num;
        int sizeoflast;
        int k;
        frag_buf_num = (size + BD_MAX_SEND_SIZE - 1) / BD_MAX_SEND_SIZE;
        sizeoflast = size % BD_MAX_SEND_SIZE;
        sizeoflast = sizeoflast ? sizeoflast : BD_MAX_SEND_SIZE;
    }*/
    desc->addr = rte_mbuf_data_dma_addr(rxm)+offset;
//    desc->tx.send_size = rte_cpu_to_le_16((uint16_t)rxm->data_len);
    desc->tx.send_size = size;
    hnae_set_bit(rrcfv, HNSV2_TXD_VLD_B,1);
    hnae_set_field(bn_pid, HNSV2_TXD_BUFNUM_M, 0, buf_num - 1);
    hnae_set_field(bn_pid, HNSV2_TXD_PORTID_M, HNSV2_TXD_PORTID_S, port_id);
/*    hnae_set_bit(rrcfv, HNSV2_TXD_L3CS_B, 1);
    hnae_set_bit(rrcfv, HNSV2_TXD_L4CS_B, 1);
    hnae_set_bit(tvsvsn, HNSV2_TXD_TSE_B, 1);
    desc->tx.ip_offset = ip_offset;
    desc->tx.tse_vlan_snap_v6_sctp_nth = tvsvsn;
    desc->tx.l4_len = 20;
    desc->tx.mss = 200;
    desc->tx.paylen = 82;
*/    //printf("data:%d,pkt:%d\n",rxm->data_len,rxm->pkt_len);

    if(first == 1){
        ip_offset = ETH_HLEN;
        if(flag & PKT_TX_VLAN_PKT)
            ip_offset += VLAN_HLEN;    

        if(rxm->packet_type & (RTE_PTYPE_L3_IPV4 | RTE_PTYPE_L3_IPV6)){
  //          printf("ipv4 or ipv6\n");
            hnae_set_bit(rrcfv, HNSV2_TXD_L4CS_B, 1);
            if(rxm->packet_type & RTE_PTYPE_L3_IPV6){
                hnae_set_bit(tvsvsn, HNSV2_TXD_IPV6_B, 1);
    //            printf("ipv6\n");
            }
            else{
                hnae_set_bit(rrcfv, HNSV2_TXD_L3CS_B, 1);
            }
            //if(rxm->ol_flags & PKT_TX_TCP_SEG){
            if(txq->hns->tso && (rxm->ol_flags & PKT_TX_TCP_SEG)){
                hnae_set_bit(tvsvsn, HNSV2_TXD_TSE_B, 1);
                mss=BD_MAX_SEND_SIZE;//rxm->tso_segsz;
                desc->tx.paylen =rte_cpu_to_le_16((uint16_t)rxm->pkt_len) ;//rte_cpu_to_le_16(paylen);
           }
        }
 //       printf("ip_offset:%d, size:%d\n",ip_offset,size);
        desc->tx.ip_offset = ip_offset;
        desc->tx.mss = rte_cpu_to_le_16(mss);
        desc->tx.tse_vlan_snap_v6_sctp_nth = tvsvsn;
        
        desc->tx.l4_len = rxm->l4_len;
    }
    
    hnae_set_bit(rrcfv, HNSV2_TXD_FE_B, frag_end);
    desc->tx.bn_pid = bn_pid;
    desc->tx.ra_ri_cs_fe_vld = rrcfv;
    txq->next_to_use++;
    if(txq->next_to_use == txq->nb_tx_desc)
        txq->next_to_use = 0;
    
//    printf("in filldesc\n");
    //    rte_hns_prefetch(desc);
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
//    printf("next_to_use:%d,next_to_clean:%d\n",txq->next_to_use,txq->next_to_clean);
//    printf("nb_pkts:%d, space:%d, txq:%d,\n",nb_pkts,tx_ring_space(txq),txq->queue_id);
    for(nb_tx = 0; nb_tx < nb_pkts; nb_tx++) {
        tx_pkt = *tx_pkts++;

        nb_buf = tx_pkt->nb_segs;
        
        if(nb_buf > tx_ring_space(txq)){
            //printf("txq:%d,result found at no ring space!\n",txq->queue_id);
           // printf("nb_buf:%d, space:%d\n",nb_buf,tx_ring_space(txq));
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
    //    printf("nb_tx:%d\n",nb_tx);
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
//    printf("next_to_use:%d,next_to_clean:%d\n",txq->next_to_use,txq->next_to_clean);
//    printf("nb_pkts:%d, space:%d, txq:%d,\n",nb_pkts,tx_ring_space(txq),txq->queue_id);
    for(nb_tx = 0; nb_tx < nb_pkts; nb_tx++) {
        tx_pkt = *tx_pkts++;

        nb_buf = tx_pkt->nb_segs;
        
        if(nb_buf > tx_ring_space(txq)){
            //printf("txq:%d,result found at no ring space!\n",txq->queue_id);
           // printf("nb_buf:%d, space:%d\n",nb_buf,tx_ring_space(txq));
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
    //    printf("nb_tx:%d\n",nb_tx);
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
};

static int
eth_hns_dev_init (struct rte_eth_dev *dev){
    struct hns_adapter *hns = dev->data->dev_private;
    struct hns_uio_ioctrl_para args;
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





/**
static struct eth_driver rte_hnsvf_pmd ={
    .platform_drv={
        .name="rte_hnsvf_pmd",
        .id_table = platform_id_hnsvf_map,
        .drv_flags = RTE_PLATFORM_DRV_NEED_MAPPING | RTE_PLATFORM_DRV_INTR_LSC,
    },
    .eth_dev_init = eth_hnsvf_dev_init,
    .eth_dev_uninit = eth_hnsvf_dev_uninit,
    .dev_private_size = sizeof (struct hns_adapter),
};
*/


static int
rte_hns_pmd_init(const char *name __rte_unused, const char *params __rte_unused)
{
    rte_eth_platform_driver_register(&rte_hns_pmd);
    return 0;
}

static int
rte_hns_pmd_uninit(const char *name)
{
    (void)name;
    return 0;
}

/**
static int
rte_hnsvf_pmd_init(const char *name __rte_unused, const char *params __rte_unused)
{
    PMD_INIT_FUNC_TRACE();
    rte_eth_platform_driver_register(&rte_hnsvf_pmd);
    return 0;
}
*/
static struct rte_driver rte_hns_driver = {
    .type = PMD_PDEV,
    .init = rte_hns_pmd_init,
    .uninit = rte_hns_pmd_uninit,
};

/**
static struct rte_driver rte_hnsvf_driver = {
    .type = PMD_PDEV,
    .init = rte_hnsvf_pmd_init,
};
*/

RTE_PMD_REGISTER_PLATFORM(net_hns, rte_hns_pmd);
/*PMD_REGISTER_DRIVER(rte_hnsvf_driver, hnsvf);*/

