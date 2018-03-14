
#ifndef _HNS_ETHDEV_H_
#define _HNS_ETHDEV_H_

#include "hns_compat.h"
#include <rte_optimization.h>
#include <rte_ring.h>

#define HNS_DEV_TO_PLATFORM(eth_dev) \
	RTE_DEV_TO_PLATFORM((eth_dev)->device)
	
#define HNS_RX_HEAD_SIZE 256
#define MAX_SKB_FRAGS 18
#define MAX_QUEUE_NUM 32

#define HNS_RCB_TX_REG_OFFSET			0x40

#define HNS_RCB_RING_MAX_BD_PER_PKT		3
#define HNS_RCB_RING_MAX_TXBD_PER_PKT		3
#define HNS_RCBV2_RING_MAX_TXBD_PER_PKT		8
#define HNS_RCB_MAX_PKT_SIZE MAC_MAX_MTU

#define HNS_RCB_RING_MAX_PENDING_BD		1024
#define HNS_RCB_RING_MIN_PENDING_BD		16

#define HNS_RCB_REG_OFFSET			0x10000

#define HNS_RCB_MAX_COALESCED_FRAMES		1023
#define HNS_RCB_MIN_COALESCED_FRAMES		1
#define HNS_RCB_DEF_COALESCED_FRAMES		50
#define HNS_RCB_CLK_FREQ_MHZ			350
#define HNS_RCB_MAX_COALESCED_USECS		0x3ff
#define HNS_RCB_DEF_COALESCED_USECS		3

#define HNS_RCB_COMMON_ENDIAN			1

#define HNS_BD_SIZE_512_TYPE			0
#define HNS_BD_SIZE_1024_TYPE			1
#define HNS_BD_SIZE_2048_TYPE			2
#define HNS_BD_SIZE_4096_TYPE			3

#define HNS_RCB_COMMON_DUMP_REG_NUM 80
#define HNS_RCB_RING_DUMP_REG_NUM 40
#define HNS_RING_STATIC_REG_NUM 28

#define HNS_DUMP_REG_NUM			500
#define HNS_STATIC_REG_NUM			12

#define HNS_TSO_MODE_8BD_32K			1
#define HNS_TSO_MDOE_4BD_16K			0

#define hnae_set_field(origin, mask, shift, val) \
	do { \
		(origin) &= (~(mask)); \
		(origin) |= ((val) << (shift)) & (mask); \
	} while (0)

#define hnae_set_bit(origin, shift, val) \
    hnae_set_field((origin), (0x1 << (shift)), (shift), (val))

#define hnae_get_field(origin, mask, shift) (((origin) & (mask)) >> (shift))

#define hnae_get_bit(origin, shift) \
    hnae_get_field((origin), (0x1 << (shift)), (shift))

/* some said the RX and TX RCB format should not be the same in the future. But
 * it is the same now...
 */
#define RCB_REG_BASEADDR_L         0x00 /* P660 support only 32bit accessing */
#define RCB_REG_BASEADDR_H         0x04
#define RCB_REG_BD_NUM             0x08
#define RCB_REG_BD_LEN             0x0C
#define RCB_REG_PKTLINE            0x10
#define RCB_REG_TAIL               0x18
#define RCB_REG_HEAD               0x1C
#define RCB_REG_FBDNUM             0x20
#define RCB_REG_OFFSET             0x24 /* pkt num to be handled */
#define RCB_REG_PKTNUM_RECORD      0x2C /* total pkt received */

#define HNS_RX_FLAG_VLAN_PRESENT 0x1
#define HNS_RX_FLAG_L3ID_IPV4 0x0
#define HNS_RX_FLAG_L3ID_IPV6 0x1
#define HNS_RX_FLAG_L4ID_UDP 0x0
#define HNS_RX_FLAG_L4ID_TCP 0x1

#define HNS_TXD_ASID_S 0
#define HNS_TXD_ASID_M (0xff << HNS_TXD_ASID_S)
#define HNS_TXD_BUFNUM_S 8
#define HNS_TXD_BUFNUM_M (0x3 << HNS_TXD_BUFNUM_S)
#define HNS_TXD_PORTID_S 10
#define HNS_TXD_PORTID_M (0x7 << HNS_TXD_PORTID_S)

#define HNS_TXD_RA_B 8
#define HNS_TXD_RI_B 9
#define HNS_TXD_L4CS_B 10
#define HNS_TXD_L3CS_B 11
#define HNS_TXD_FE_B 12
#define HNS_TXD_VLD_B 13
#define HNS_TXD_IPOFFSET_S 14
#define HNS_TXD_IPOFFSET_M (0xff << HNS_TXD_IPOFFSET_S)

#define HNS_RXD_IPOFFSET_S 0
#define HNS_RXD_IPOFFSET_M (0xff << HNS_TXD_IPOFFSET_S)
#define HNS_RXD_BUFNUM_S 8
#define HNS_RXD_BUFNUM_M (0x3 << HNS_RXD_BUFNUM_S)
#define HNS_RXD_PORTID_S 10
#define HNS_RXD_PORTID_M (0x7 << HNS_RXD_PORTID_S)
#define HNS_RXD_DMAC_S 13
#define HNS_RXD_DMAC_M (0x3 << HNS_RXD_DMAC_S)
#define HNS_RXD_VLAN_S 15
#define HNS_RXD_VLAN_M (0x3 << HNS_RXD_VLAN_S)
#define HNS_RXD_L3ID_S 17
#define HNS_RXD_L3ID_M (0xf << HNS_RXD_L3ID_S)
#define HNS_RXD_L4ID_S 21
#define HNS_RXD_L4ID_M (0xf << HNS_RXD_L4ID_S)
#define HNS_RXD_FE_B 25
#define HNS_RXD_FRAG_B 26
#define HNS_RXD_VLD_B 27
#define HNS_RXD_L2E_B 28
#define HNS_RXD_L3E_B 29
#define HNS_RXD_L4E_B 30
#define HNS_RXD_DROP_B 31

#define HNS_RXD_VLANID_S 8
#define HNS_RXD_VLANID_M (0xfff << HNS_RXD_VLANID_S)
#define HNS_RXD_CFI_B 20
#define HNS_RXD_PRI_S 21
#define HNS_RXD_PRI_M (0x7 << HNS_RXD_PRI_S)
#define HNS_RXD_ASID_S 24
#define HNS_RXD_ASID_M (0xff << HNS_RXD_ASID_S)

#define HNSV2_TXD_BUFNUM_S 0
#define HNSV2_TXD_BUFNUM_M (0x7 << HNSV2_TXD_BUFNUM_S)
#define HNSV2_TXD_PORTID_S	4
#define HNSV2_TXD_PORTID_M	(0X7 << HNSV2_TXD_PORTID_S)
#define HNSV2_TXD_RI_B   1
#define HNSV2_TXD_L4CS_B   2
#define HNSV2_TXD_L3CS_B   3
#define HNSV2_TXD_FE_B   4
#define HNSV2_TXD_VLD_B  5

#define HNSV2_TXD_TSE_B   0
#define HNSV2_TXD_VLAN_EN_B   1
#define HNSV2_TXD_SNAP_B   2
#define HNSV2_TXD_IPV6_B   3
#define HNSV2_TXD_SCTP_B   4

#define __packed __attribute__((packed))
/* hardware spec ring buffer format */
__packed struct hnae_desc {
	__le64 addr;
	union {
		struct {
			union {
				__le16 asid_bufnum_pid;
				__le16 asid;
			};
			__le16 send_size;
			union {
				__le32 flag_ipoffset;
				struct {
					__u8 bn_pid;
					__u8 ra_ri_cs_fe_vld;
					__u8 ip_offset;
					__u8 tse_vlan_snap_v6_sctp_nth;
				};
			};
			__le16 mss;
			__u8 l4_len;
			__u8 reserved1;
			__le16 paylen;
			__u8 vmid;
			__u8 qid;
			__le32 reserved2[2];
		} tx;

		struct {
			__le32 ipoff_bnum_pid_flag;
			__le16 pkt_len;
			__le16 size;
			union {
				__le32 vlan_pri_asid;
				struct {
					__le16 asid;
					__le16 vlan_cfi_pri;
				};
			};
			__le32 rss_hash;
			__le32 reserved_1[2];
		} rx;
	};
};

struct hns_uio_ioctrl_para {
    unsigned long long index;
    unsigned long long cmd;
    unsigned long long value;
    unsigned char data[200];
};

enum  {
	HNS_UIO_IOCTL_MAC = 0,
	HNS_UIO_IOCTL_UP,
	HNS_UIO_IOCTL_DOWN,
	HNS_UIO_IOCTL_PORT,
	HNS_UIO_IOCTL_VF_MAX,
	HNS_UIO_IOCTL_VF_ID,
	HNS_UIO_IOCTL_VF_START,
	HNS_UIO_IOCTL_QNUM,
	HNS_UIO_IOCTL_MTU,
	HNS_UIO_IOCTL_GET_STAT,
	HNS_UIO_IOCTL_GET_LINK,
	HNS_UIO_IOCTL_REG_READ,
	HNS_UIO_IOCTL_REG_WRITE,
	HNS_UIO_IOCTL_SET_PAUSE,
	HNS_UIO_IOCTL_NUM,
    HNS_UIO_IOCTL_LINK_UPDATE,
    HNS_UIO_IOCTL_INIT_MAC,
    HNS_UIO_IOCTL_PROMISCUOUS,
    HNS_UIO_IOCTL_TSO
};

struct hns_rx_entry {
    struct rte_mbuf *mbuf;
};

struct hns_tx_entry {
    struct rte_mbuf *mbuf;
    uint16_t next_id;
    uint16_t last_id;
};

struct hns_rx_queue{
    struct rte_mempool *mb_pool;
    struct hnae_desc *rx_ring;
    struct hns_rx_entry *sw_ring;
    struct hns_adapter *hns;
    
    struct rte_mbuf *pkt_first_seg;
    struct rte_mbuf *pkt_last_seg;
    uint16_t current_num;

    uint16_t queue_id;
    uint16_t port_id;
    uint16_t nb_rx_desc;
    uint16_t nb_rx_hold;
    uint16_t rx_tail;
    uint16_t next_to_clean;
    uint16_t next_to_use;
    uint16_t rx_free_thresh;

//#ifdef OPTIMIZATION
//    struct rte_ring* cache_ring;
//#endif
};

struct hns_tx_queue{
    struct hnae_desc *tx_ring;
    struct hns_adapter *hns;
    struct hns_tx_entry *sw_ring;

    uint16_t queue_id;
    uint16_t nb_tx_desc;
    uint16_t next_to_clean;
    uint16_t next_to_use;
    uint16_t nb_hold;
};

/*
struct hns_ring{
    struct hnae_desc *desc;

    struct rte_mbuf *pkt_first_seg;
    struct rte_mbuf *pkt_last_seg;

    uint16_t queue_id;
    uint16_t nb_desc;
    
    int next_to_use;
    int nest_clean;

}*/

struct hns_stats {
    uint64_t io_err_cnt;
    uint64_t sw_err_cnt;
    uint64_t seg_pkt_cnt;
    uint64_t tx_pkts;
    uint64_t tx_bytes;
    uint64_t tx_err_cnt;
    uint64_t rx_pkts;
    uint64_t rx_bytes;
    uint64_t rx_err_cnt;

};

struct hns_adapter {
    void *phy_base;
    void *io_base;
    int cdev_fd;
    int uio_index;
    int stopped;
    unsigned int port;
    unsigned int vf_sum;
    unsigned int vf_id;
    unsigned int uio_start;
    unsigned int q_num;
    unsigned int desc_num_per_rxq;
    unsigned int desc_num_per_txq;
    struct hnae_desc *rx_desc[MAX_QUEUE_NUM];
    struct hnae_desc *tx_desc[MAX_QUEUE_NUM];
    struct hns_tx_queue *txq[MAX_QUEUE_NUM];
    struct hns_stats stats;
    int tso;
};

void eth_hns_rx_queue_release(void *queue);
void eth_hns_tx_queue_release(void *queue);

#endif
