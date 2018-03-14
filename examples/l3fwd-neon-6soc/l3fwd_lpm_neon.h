/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2016 Intel Corporation. All rights reserved.
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

#ifndef __L3FWD_LPM_NEON_H__
#define __L3FWD_LPM_NEON_H__

#include "l3fwd_neon.h"

const int8_t port_table[] = {0, 0, 0, 0, 0, 8, 5, 0, 6}; 

static inline __attribute__((always_inline)) uint16_t
lpm_get_dst_port(const struct lcore_conf *qconf, struct rte_mbuf *pkt,
		uint8_t portid)
{
	uint32_t next_hop;
	//struct ipv6_hdr *ipv6_hdr;
	struct ipv4_hdr *ipv4_hdr;
	struct ether_hdr *eth_hdr;

	if (RTE_ETH_IS_IPV4_HDR(pkt->packet_type)) {

		eth_hdr = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
		ipv4_hdr = (struct ipv4_hdr *)(eth_hdr + 1);

		return (uint16_t) (
			(rte_lpm_lookup(qconf->ipv4_lookup_struct,
					rte_be_to_cpu_32(ipv4_hdr->dst_addr),
					&next_hop) == 0) ?
						next_hop : portid);

	} else if (RTE_ETH_IS_IPV6_HDR(pkt->packet_type)) {

//		eth_hdr = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
//		ipv6_hdr = (struct ipv6_hdr *)(eth_hdr + 1);

//		return (uint16_t) ((rte_lpm6_lookup(qconf->ipv6_lookup_struct,
//				ipv6_hdr->dst_addr, &next_hop) == 0)
//				? next_hop : portid);
        return portid;
	}

	return portid;
}

/*
 * lpm_get_dst_port optimized routine for packets where dst_ipv4 is already
 * precalculated. If packet is ipv6 dst_addr is taken directly from packet
 * header and dst_ipv4 value is not used.
 */
static inline __attribute__((always_inline)) uint16_t
lpm_get_dst_port_with_ipv4(const struct lcore_conf *qconf, struct rte_mbuf *pkt,
	uint32_t dst_ipv4, uint8_t portid)
{
	uint32_t next_hop;
	struct ipv6_hdr *ipv6_hdr;
	struct ether_hdr *eth_hdr;

	if (RTE_ETH_IS_IPV4_HDR(pkt->packet_type)) {
		return (uint16_t) ((rte_lpm_lookup(qconf->ipv4_lookup_struct, dst_ipv4,
			&next_hop) == 0) ? next_hop : portid);

	} else if (RTE_ETH_IS_IPV6_HDR(pkt->packet_type)) {

		eth_hdr = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
		ipv6_hdr = (struct ipv6_hdr *)(eth_hdr + 1);

		return (uint16_t) ((rte_lpm6_lookup(qconf->ipv6_lookup_struct,
				ipv6_hdr->dst_addr, &next_hop) == 0)
				? next_hop : portid);

	}

	return portid;

}

/*
 * Read packet_type and destination IPV4 addresses from 4 mbufs.
 */
static inline void
processx4_step1(struct rte_mbuf *pkt[FWDSTEP],
		int32x4_t *dip,
		uint32_t *ipv4_flag)
{
	struct ipv4_hdr *ipv4_hdr;
	struct ether_hdr *eth_hdr;
	int32_t x[4];

	eth_hdr = rte_pktmbuf_mtod(pkt[0], struct ether_hdr *);
	ipv4_hdr = (struct ipv4_hdr *)(eth_hdr + 1);
	x[0] = ipv4_hdr->dst_addr;
	//printf("x0 = %d\n", x[0]);
	ipv4_flag[0] = pkt[0]->packet_type & RTE_PTYPE_L3_IPV4;

	eth_hdr = rte_pktmbuf_mtod(pkt[1], struct ether_hdr *);
	ipv4_hdr = (struct ipv4_hdr *)(eth_hdr + 1);
	x[1] = ipv4_hdr->dst_addr;
	//printf("x1 = %d\n", x[1]);
	ipv4_flag[0] &= pkt[1]->packet_type;

	eth_hdr = rte_pktmbuf_mtod(pkt[2], struct ether_hdr *);
	ipv4_hdr = (struct ipv4_hdr *)(eth_hdr + 1);
	x[2] = ipv4_hdr->dst_addr;
	//printf("x2 = %d\n", x[2]);
	ipv4_flag[0] &= pkt[2]->packet_type;

	eth_hdr = rte_pktmbuf_mtod(pkt[3], struct ether_hdr *);
	ipv4_hdr = (struct ipv4_hdr *)(eth_hdr + 1);
	x[3] = ipv4_hdr->dst_addr;
	//printf("x3 = %d\n", x[3]);
	ipv4_flag[0] &= pkt[3]->packet_type;

	dip[0] = vld1q_s32(x);
	/*	int32_t dpi = vgetq_lane_s32(dip[0], 0);
				printf("dip[0] = %d\n",  dpi);
	     dpi = vgetq_lane_s32(dip[0], 1);
				printf("dip[1] = %d\n",  dpi);
		 dpi = vgetq_lane_s32(dip[0], 2);
				printf("dip[2] = %d\n", dpi);
		 dpi = vgetq_lane_s32(dip[0], 3);
		printf("dip[3] = %d\n", dpi);*/
}

/*
 * Lookup into LPM for destination port.
 * If lookup fails, use incoming port (portid) as destination port.
 */
static inline void
processx4_step2(const struct lcore_conf *qconf,
		int32x4_t dip,
		uint32_t ipv4_flag,
		uint8_t portid,
		struct rte_mbuf *pkt[FWDSTEP],
		uint16_t dprt[FWDSTEP])
{
	rte_xmm_t dst;
	
	/* Byte swap 4 IPV4 addresses. */
	//dip = vrev64q_s32(dip);
	/* int32_t dpi = vgetq_lane_s32(dip, 0);
				printf("dip[0] = %x\n",  dpi);
	     dpi = vgetq_lane_s32(dip, 1);
				printf("dip[1] = %x\n",  dpi);
		 dpi = vgetq_lane_s32(dip, 2);
				printf("dip[2] = %x\n", dpi);
		 dpi = vgetq_lane_s32(dip, 3);
		printf("dip[3] = %x\n", dpi); */
	uint8x16_t bswap_mask = {15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0};
	dip = vreinterpretq_s32_s8(vqtbl1q_s8(vreinterpretq_s8_s32(dip), bswap_mask));
	
	 //int32_t dpi = vgetq_lane_s32(dip, 0);
				// printf("2   dip[0] = %x\n",  dpi);
	    //  dpi = vgetq_lane_s32(dip, 1);
				// printf("2   dip[1] = %x\n",  dpi);
		//  dpi = vgetq_lane_s32(dip, 2);
				// printf("2   dip[2] = %x\n", dpi);
		//  dpi = vgetq_lane_s32(dip, 3);
		// printf("2    dip[3] = %x\n", dpi);
	
	/* if all 4 packets are IPV4. */
	if (likely(ipv4_flag)) {
		rte_lpm_lookupx4(qconf->ipv4_lookup_struct, dip, dst.u32,
			portid);
		/*for (int i = 0; i < 4; i++)
		{
			printf("portid\n");
		}*/
		/* get rid of unused upper 16 bit for each dport. */
		/*int32_t dpi = vgetq_lane_s32(dst.x, 0);
				printf("dst.x = %d\n",  dpi);
	     dpi = vgetq_lane_s32(dst.x, 1);
				printf("dst.x = %d\n",  dpi);
		 dpi = vgetq_lane_s32(dst.x, 2);
				printf("dst.x = %d\n", dpi);
		 dpi = vgetq_lane_s32(dst.x, 3);
		printf("dst.x = %d\n", dpi);*/
		uint8x16_t swap_mask2 = {0, 1, 0, 1, 4, 5, 4, 5, 8, 9, 8, 9, 12, 13, 12, 13};
	    dst.x = vreinterpretq_s32_s8(vqtbl1q_s8(vreinterpretq_s8_s32(dst.x), swap_mask2));
		/* dpi = vgetq_lane_s32(dst.x, 0);
				printf("2   dst.x = %d\n",  dpi);
	     dpi = vgetq_lane_s32(dst.x, 1);
				printf("2   dst.x = %d\n",  dpi);
		 dpi = vgetq_lane_s32(dst.x, 2);
				printf("2   dst.x = %d\n", dpi);
		 dpi = vgetq_lane_s32(dst.x, 3);
		printf("2    dst.x = %d\n", dpi);*/
		*(uint64_t *)dprt = dst.u64[0];
		/*int8x16_t ipc = vreinterpretq_s8_s32(dip),
		ipc = vsetq_lane_s8(0, ipc, (int16_t)dprt[0]);
		ipc = vsetq_lane_s8(4, ipc, (int16_t)dprt[1]);
		ipc = vsetq_lane_s8(8, ipc, (int16_t)dprt[2]);
		ipc = vsetq_lane_s8(12, ipc, (int16_t)dprt[3]);
		dip = vreinterpretq_s32_s8(ipc);*/
	} else {
		dst.x = dip;
		dprt[0] = lpm_get_dst_port_with_ipv4(qconf, pkt[0], dst.u32[0], portid);
		dprt[1] = lpm_get_dst_port_with_ipv4(qconf, pkt[1], dst.u32[1], portid);
		dprt[2] = lpm_get_dst_port_with_ipv4(qconf, pkt[2], dst.u32[2], portid);
		dprt[3] = lpm_get_dst_port_with_ipv4(qconf, pkt[3], dst.u32[3], portid);
	}
}


/*
 * Read packet_type and destination IPV4 addresses from 4 mbufs.
 */
static inline void
processx4_step1_2(struct rte_mbuf *pkt[FWDSTEP], uint16_t dst_port)
{
	struct ipv4_hdr *ipv4_hdr;
	struct ether_hdr *eth_hdr;
	uint32_t new_dst_addr;
	
    new_dst_addr = 0x10100 + port_table[dst_port] + 1;
	
	
	
	eth_hdr = rte_pktmbuf_mtod(pkt[0], struct ether_hdr *);
	ipv4_hdr = (struct ipv4_hdr *)(eth_hdr + 1);
	
	//printf("ori_dst_addr = %x\n", ipv4_hdr->dst_addr);
	//printf("new_dst_addr = %x\n", new_dst_addr);
	
	ipv4_hdr->dst_addr = new_dst_addr;

}


 static inline void
show_ip_address(struct rte_mbuf *pkt[FWDSTEP])
{
	struct ipv4_hdr *ipv4_hdr;
	struct ether_hdr *eth_hdr;
	
	
	
	eth_hdr = rte_pktmbuf_mtod(pkt[0], struct ether_hdr *);
	ipv4_hdr = (struct ipv4_hdr *)(eth_hdr + 1);
	
	printf("ori_dst_addr = %x\n", ipv4_hdr->dst_addr);

	

} 

/*
 * Buffer optimized handling of packets, invoked
 * from main_loop.
 */
static inline void
l3fwd_lpm_send_packets(int nb_rx, struct rte_mbuf **pkts_burst,
			uint8_t portid, struct lcore_conf *qconf)
{
	int32_t j = 0;
	uint16_t dst_port[MAX_PKT_BURST];
	int32x4_t dip[MAX_PKT_BURST / FWDSTEP];
	uint32_t ipv4_flag[MAX_PKT_BURST / FWDSTEP];
	const int32_t k = RTE_ALIGN_FLOOR(nb_rx, FWDSTEP);

	
	for (j = 0; j != k; j += FWDSTEP)
	{
		//printf("processx4_step1 j = %d\n", j);
		processx4_step1(&pkts_burst[j], &dip[j / FWDSTEP],
				&ipv4_flag[j / FWDSTEP]);
	}
	
	/*for (int i=0; i<MAX_PKT_BURST; i++)
	{
		printf("dst_port[%d] = %d\n", i, dst_port[i]);
	   	
	}*/

	for (j = 0; j != k; j += FWDSTEP)
	{
		//printf("processx4_step2 j = %d\n", j);
		processx4_step2(qconf, dip[j / FWDSTEP],
				ipv4_flag[j / FWDSTEP], portid, &pkts_burst[j], &dst_port[j]);
	}
	
	/*for (int i=0; i<MAX_PKT_BURST; i++)
	{
		printf("2        dst_port[%d] = %d\n", i, dst_port[i]);
	   	
	}*/

	/* Classify last up to 3 packets one by one */
	switch (nb_rx % FWDSTEP) {
	case 3:
		dst_port[j] = lpm_get_dst_port(qconf, pkts_burst[j], portid);
		j++;
	case 2:
		dst_port[j] = lpm_get_dst_port(qconf, pkts_burst[j], portid);
		j++;
	case 1:
		dst_port[j] = lpm_get_dst_port(qconf, pkts_burst[j], portid);
		j++;
	}
    //printf("send_packets_multi nb_rx = %d\n", nb_rx);
	
	//for (j = 0; j < nb_rx; j++)
	//{
		
		
		
	    //if (portid == 5)
	    //{ 	
	    //   show_ip_address(&pkts_burst[j]);
		//}
		
		
		//if (portid == 5)		
		//	printf("dst_port6 = %d\n", dst_port[j]);
		
		//processx4_step1_2(&pkts_burst[j], dst_port[j]);
		
	//}
	
	
	for (j = 0; j<nb_rx; j++)
	{
		switch (portid) {
	    case 4:
		    dst_port[j] = 9;
            break;
	    case 5:
		    dst_port[j] = 6;
		    break;
	    case 6:
		    dst_port[j] = 5;
		    break;
		case 7:
		    dst_port[j] = 7;
            break;
	    case 8:
		    dst_port[j] = 8;
		    break;
	    case 9:
		    dst_port[j] = 4;
		    break;
		default:
		    dst_port[j] = portid;
	}

    }
	
	
	send_packets_multi(qconf, pkts_burst, dst_port, nb_rx);
}

#endif /* __L3FWD_LPM_SSE_H__ */
