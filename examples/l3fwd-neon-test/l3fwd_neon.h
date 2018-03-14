/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2016 Intel Corporation. All rights reserved.
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


#ifndef _L3FWD_COMMON_H_
#define _L3FWD_COMMON_H_

#include "l3fwd.h"

#ifdef DO_RFC_1812_CHECKS

#define	IPV4_MIN_VER_IHL	0x45
#define	IPV4_MAX_VER_IHL	0x4f
#define	IPV4_MAX_VER_IHL_DIFF	(IPV4_MAX_VER_IHL - IPV4_MIN_VER_IHL)

/* Minimum value of IPV4 total length (20B) in network byte order. */
#define	IPV4_MIN_LEN_BE	(sizeof(struct ipv4_hdr) << 8)

//uint16_t me[8] = {0, 0, 1, 1, 1, 1, 1, 1};
//const uint16x8_t mask_eth = vld1q_u16(me);
const uint32x4_t mask_eth = {0xffffffff, 0, 0, 0};
extern int tx_count[RTE_MAX_LCORE];

/*
 * From http://www.rfc-editor.org/rfc/rfc1812.txt section 5.2.2:
 * - The IP version number must be 4.
 * - The IP header length field must be large enough to hold the
 *    minimum length legal IP datagram (20 bytes = 5 words).
 * - The IP total length field must be large enough to hold the IP
 *   datagram header, whose length is specified in the IP header length
 *   field.
 * If we encounter invalid IPV4 packet, then set destination port for it
 * to BAD_PORT value.
 */
static inline __attribute__((always_inline)) void
rfc1812_process(struct ipv4_hdr *ipv4_hdr, uint16_t *dp, uint32_t ptype)
{
	//uint8_t ihl;

	if (RTE_ETH_IS_IPV4_HDR(ptype)) {
		//printf("rfc1812 ipv4_hdr.version_ihl = %x\n", ipv4_hdr->version_ihl);
		//ihl = ipv4_hdr->version_ihl - IPV4_MIN_VER_IHL;

		ipv4_hdr->time_to_live--;
		ipv4_hdr->hdr_checksum++;

		if //(ihl > IPV4_MAX_VER_IHL_DIFF ||
				((uint8_t)ipv4_hdr->total_length == 0 &&
				ipv4_hdr->total_length < IPV4_MIN_LEN_BE)//)
				{
					//printf("rfc1812 ipv4_hdr.total_length = %d\n", ipv4_hdr->total_length);
					//printf("rfc1812 ipv4_hdr.src_addr = %x\n", ipv4_hdr->src_addr);
					//printf("rfc1812 ipv4_hdr.dst_addr = %x\n", ipv4_hdr->dst_addr);
			        dp[0] = BAD_PORT;			  
				}

	}
}

#else
#define	rfc1812_process(mb, dp, ptype)	do { } while (0)
#endif /* DO_RFC_1812_CHECKS */

/*
 * Update source and destination MAC addresses in the ethernet header.
 * Perform RFC1812 checks and updates for IPV4 packets.
 */
static inline void
processx4_step3(struct rte_mbuf *pkt[FWDSTEP], uint16_t dst_port[FWDSTEP])
{
	int32x4_t te[FWDSTEP];
	int32x4_t ve[FWDSTEP];
	int32_t *p[FWDSTEP];
	//printf("processx4_step3 1\n");
	p[0] = rte_pktmbuf_mtod(pkt[0], int32_t *);
	p[1] = rte_pktmbuf_mtod(pkt[1], int32_t *);
	p[2] = rte_pktmbuf_mtod(pkt[2], int32_t *);
	p[3] = rte_pktmbuf_mtod(pkt[3], int32_t *);
	//printf("processx4_step3 2\n");

	
	ve[0] = val_eth[dst_port[0]];
	te[0] = vld1q_s32(p[0]);

	ve[1] = val_eth[dst_port[1]];
	te[1] = vld1q_s32(p[1]);

	ve[2] = val_eth[dst_port[2]];
	te[2] = vld1q_s32(p[2]);

	ve[3] = val_eth[dst_port[3]];
	te[3] = vld1q_s32(p[3]);

	//printf("processx4_step3 3\n");
	
	/* Update first 12 bytes, keep rest bytes intact. */
	/*int32_t dpi = vgetq_lane_s32(te[0], 0);
				printf("te[0][0] = %d\n",  dpi);
	     dpi = vgetq_lane_s32(te[0], 1);
				printf("te[0][1] = %d\n",  dpi);
		 dpi = vgetq_lane_s32(te[0], 2);
				printf("te[0][2] = %d\n", dpi);
		 dpi = vgetq_lane_s32(te[0], 3);
		printf("te[0][3] = %d\n", dpi);
		dpi = vgetq_lane_s32(ve[0], 0);
				printf("ve[0][0] = %d\n",  dpi);
	     dpi = vgetq_lane_s32(ve[0], 1);
				printf("ve[0][1] = %d\n",  dpi);
		 dpi = vgetq_lane_s32(ve[0], 2);
				printf("ve[0][2] = %d\n", dpi);
		 dpi = vgetq_lane_s32(ve[0], 3);
		printf("ve[0][3] = %d\n", dpi);*/
	te[0] =  vbslq_s32(mask_eth, te[0], ve[0]);
	te[1] =  vbslq_s32(mask_eth, te[1], ve[1]);
	te[2] =  vbslq_s32(mask_eth, te[2], ve[2]);
	te[3] =  vbslq_s32(mask_eth, te[3], ve[3]);
	/*dpi = vgetq_lane_s32(te[0], 0);
				printf("2       te[0][0] = %d\n",  dpi);
	     dpi = vgetq_lane_s32(te[0], 1);
				printf("2      te[0][1] = %d\n",  dpi);
		 dpi = vgetq_lane_s32(te[0], 2);
				printf("2       te[0][2] = %d\n", dpi);
		 dpi = vgetq_lane_s32(te[0], 3);
		printf("2         te[0][3] = %d\n", dpi);*/


	//for (int i = 0; i < FWDSTEP; i++)
	//	printf("3   dst_port[%d] = %d\n", i, dst_port[i]);	
	
	vst1q_s32(p[0], te[0]);
	vst1q_s32(p[1], te[1]);
	vst1q_s32(p[2], te[2]);
	vst1q_s32(p[3], te[3]);
	

	rfc1812_process((struct ipv4_hdr *)((struct ether_hdr *)p[0] + 1),
		&dst_port[0], pkt[0]->packet_type);
	rfc1812_process((struct ipv4_hdr *)((struct ether_hdr *)p[1] + 1),
		&dst_port[1], pkt[1]->packet_type);
	rfc1812_process((struct ipv4_hdr *)((struct ether_hdr *)p[2] + 1),
		&dst_port[2], pkt[2]->packet_type);
	rfc1812_process((struct ipv4_hdr *)((struct ether_hdr *)p[3] + 1),
		&dst_port[3], pkt[3]->packet_type);
}

/*
 * We group consecutive packets with the same destionation port into one burst.
 * To avoid extra latency this is done together with some other packet
 * processing, but after we made a final decision about packet's destination.
 * To do this we maintain:
 * pnum - array of number of consecutive packets with the same dest port for
 * each packet in the input burst.
 * lp - pointer to the last updated element in the pnum.
 * dlp - dest port value lp corresponds to.
 */

#define	GRPSZ	(1 << FWDSTEP)
#define	GRPMSK	(GRPSZ - 1)

#define GROUP_PORT_STEP(dlp, dcp, lp, pn, idx)	do { \
	if (likely((dlp) == (dcp)[(idx)])) {             \
		(lp)[0]++;                                   \
	} else {                                         \
		(dlp) = (dcp)[idx];                          \
		(lp) = (pn) + (idx);                         \
		(lp)[0] = 1;                                 \
	}                                                \
} while (0)

/*
 * Group consecutive packets with the same destination port in bursts of 4.
 * Suppose we have array of destionation ports:
 * dst_port[] = {a, b, c, d,, e, ... }
 * dp1 should contain: <a, b, c, d>, dp2: <b, c, d, e>.
 * We doing 4 comparisions at once and the result is 4 bit mask.
 * This mask is used as an index into prebuild array of pnum values.
 */
static inline uint16_t *
port_groupx4(uint16_t pn[FWDSTEP + 1], uint16_t *lp, int32x4_t dp1, int32x4_t dp2)
{
	static const struct {
		uint64_t pnum; /* prebuild 4 values for pnum[]. */
		int32_t  idx;  /* index for new last updated elemnet. */
		uint16_t lpv;  /* add value to the last updated element. */
	} gptbl[GRPSZ] = {
	{
		/* 0: a != b, b != c, c != d, d != e */
		.pnum = UINT64_C(0x0001000100010001),
		.idx = 4,
		.lpv = 0,
	},
	{
		/* 1: a == b, b != c, c != d, d != e */
		.pnum = UINT64_C(0x0001000100010002),
		.idx = 4,
		.lpv = 1,
	},
	{
		/* 2: a != b, b == c, c != d, d != e */
		.pnum = UINT64_C(0x0001000100020001),
		.idx = 4,
		.lpv = 0,
	},
	{
		/* 3: a == b, b == c, c != d, d != e */
		.pnum = UINT64_C(0x0001000100020003),
		.idx = 4,
		.lpv = 2,
	},
	{
		/* 4: a != b, b != c, c == d, d != e */
		.pnum = UINT64_C(0x0001000200010001),
		.idx = 4,
		.lpv = 0,
	},
	{
		/* 5: a == b, b != c, c == d, d != e */
		.pnum = UINT64_C(0x0001000200010002),
		.idx = 4,
		.lpv = 1,
	},
	{
		/* 6: a != b, b == c, c == d, d != e */
		.pnum = UINT64_C(0x0001000200030001),
		.idx = 4,
		.lpv = 0,
	},
	{
		/* 7: a == b, b == c, c == d, d != e */
		.pnum = UINT64_C(0x0001000200030004),
		.idx = 4,
		.lpv = 3,
	},
	{
		/* 8: a != b, b != c, c != d, d == e */
		.pnum = UINT64_C(0x0002000100010001),
		.idx = 3,
		.lpv = 0,
	},
	{
		/* 9: a == b, b != c, c != d, d == e */
		.pnum = UINT64_C(0x0002000100010002),
		.idx = 3,
		.lpv = 1,
	},
	{
		/* 0xa: a != b, b == c, c != d, d == e */
		.pnum = UINT64_C(0x0002000100020001),
		.idx = 3,
		.lpv = 0,
	},
	{
		/* 0xb: a == b, b == c, c != d, d == e */
		.pnum = UINT64_C(0x0002000100020003),
		.idx = 3,
		.lpv = 2,
	},
	{
		/* 0xc: a != b, b != c, c == d, d == e */
		.pnum = UINT64_C(0x0002000300010001),
		.idx = 2,
		.lpv = 0,
	},
	{
		/* 0xd: a == b, b != c, c == d, d == e */
		.pnum = UINT64_C(0x0002000300010002),
		.idx = 2,
		.lpv = 1,
	},
	{
		/* 0xe: a != b, b == c, c == d, d == e */
		.pnum = UINT64_C(0x0002000300040001),
		.idx = 1,
		.lpv = 0,
	},
	{
		/* 0xf: a == b, b == c, c == d, d == e */
		.pnum = UINT64_C(0x0002000300040005),
		.idx = 0,
		.lpv = 4,
	},
	};

	union {
		uint16_t u16[FWDSTEP + 1];
		uint64_t u64;
	} *pnum = (void *)pn;

	uint32_t v = 0;

	//dp1 = _mm_cmpeq_epi16(dp1, dp2);
	uint32x4_t dp3 = vceqq_s32(dp1, dp2);
	for (int i=0; i<4; i++)
	{
		uint32_t dpi = vgetq_lane_u32(dp3, i);
		if (dpi == 0xffffffff)
			v++;
		if (i < 4)
		    v = v << 1;
	}
	v = 15;
	//printf("v=%d\n", v);
	//dp1 = _mm_unpacklo_epi16(dp1, dp1);
	//v = _mm_movemask_ps((__m128)dp1);

	/* update last port counter. */
	lp[0] += gptbl[v].lpv;

	/* if dest port value has changed. */
	if (v != GRPMSK) {
		pnum->u64 = gptbl[v].pnum;
		pnum->u16[FWDSTEP] = 1;
		lp = pnum->u16 + gptbl[v].idx;
	}

	return lp;
}

/**
 * Process one packet:
 * Update source and destination MAC addresses in the ethernet header.
 * Perform RFC1812 checks and updates for IPV4 packets.
 */
static inline void
process_packet(struct rte_mbuf *pkt, uint16_t *dst_port)
{
	struct ether_hdr *eth_hdr;
	int32x4_t te, ve;

	eth_hdr = rte_pktmbuf_mtod(pkt, struct ether_hdr *);

	//const uint16x8_t *eth_hdr_ld = (uint16x8_t *)eth_hdr;
	
	te = vld1q_s32((int32_t *)eth_hdr);
	ve = val_eth[dst_port[0]];

	rfc1812_process((struct ipv4_hdr *)(eth_hdr + 1), dst_port,
			pkt->packet_type);

	te = vbslq_s32(mask_eth, te, ve);
	vst1q_s32((int32_t *)eth_hdr, te);
}

static inline __attribute__((always_inline)) void
send_packetsx4(struct lcore_conf *qconf, uint8_t port, struct rte_mbuf *m[],
		uint32_t num)
{
	uint32_t len, j, n;

	len = qconf->tx_mbufs[port].len;

	/*
	 * If TX buffer for that queue is empty, and we have enough packets,
	 * then send them straightway.
	 */
	if (num >= MAX_TX_BURST && len == 0) {
		//if (port == 6)
		//   printf(" rte_eth_tx_burst port = %d     num = %d\n", port, num);
	   //if (port == 8)
		//   printf("8  rte_eth_tx_burst port = %d     num = %d\n", port, num);

		n = rte_eth_tx_burst(port, qconf->tx_queue_id[port], m, num);
		tx_count[port]+=n;
		//if (n != 0)
		//if (port == 6)	
		//printf(" n = %d\n", n);
		if (unlikely(n < num)) {
			do {
				rte_pktmbuf_free(m[n]);
			} while (++n < num);
		}
		return;
	}
	/*
	 * Put packets into TX buffer for that queue.
	 */

	n = len + num;
	n = (n > MAX_PKT_BURST) ? MAX_PKT_BURST - len : num;

	/* j = 0;
	switch (n % FWDSTEP) {
	while (j < n) {
	case 0:
		qconf->tx_mbufs[port].m_table[len + j] = m[j];
		j++;
	case 3:
		qconf->tx_mbufs[port].m_table[len + j] = m[j];
		j++;
	case 2:
		qconf->tx_mbufs[port].m_table[len + j] = m[j];
		j++;
	case 1:
		qconf->tx_mbufs[port].m_table[len + j] = m[j];
		j++;
	}
	} */
	
	j = 0;
	uint n1 = n &(~3);
	while (j < n1) {
		qconf->tx_mbufs[port].m_table[len + j] = m[j];
		qconf->tx_mbufs[port].m_table[len + j+1] = m[j+1];
		qconf->tx_mbufs[port].m_table[len + j+2] = m[j+2];
		qconf->tx_mbufs[port].m_table[len + j+3] = m[j+3];
		j+=4;
	}
	switch (n % FWDSTEP) {
	case 0:
		qconf->tx_mbufs[port].m_table[len + j] = m[j];
		j++;
	case 3:
		qconf->tx_mbufs[port].m_table[len + j] = m[j];
		j++;
	case 2:
		qconf->tx_mbufs[port].m_table[len + j] = m[j];
		j++;
	case 1:
		qconf->tx_mbufs[port].m_table[len + j] = m[j];
		j++;
	}
	
	len += n;
    
	/* enough pkts to be sent */
	if (unlikely(len == MAX_PKT_BURST)) {
        //printf("1");
		send_burst(qconf, MAX_PKT_BURST, port);
		//printf("2\n");

		/* copy rest of the packets into the TX buffer. */
		len = num - n;
		j = 0;
		/* switch (len % FWDSTEP) {
		while (j < len) {
		case 0:
			qconf->tx_mbufs[port].m_table[j] = m[n + j];
			j++;
		case 3:
			qconf->tx_mbufs[port].m_table[j] = m[n + j];
			j++;
		case 2:
			qconf->tx_mbufs[port].m_table[j] = m[n + j];
			j++;
		case 1:
			qconf->tx_mbufs[port].m_table[j] = m[n + j];
			j++;
		}
		} */
	    n1 = len &(~3);
		while (j < n1) {
			qconf->tx_mbufs[port].m_table[ j] = m[n+j];
			qconf->tx_mbufs[port].m_table[ j+1] = m[n+j+1];
			qconf->tx_mbufs[port].m_table[ j+2] = m[n+j+2];
			qconf->tx_mbufs[port].m_table[ j+3] = m[n+j+3];
			j+=4;
		}
		switch (len % FWDSTEP) {
		case 0:
			qconf->tx_mbufs[port].m_table[ j] = m[n+j];
			j++;
		case 3:
			qconf->tx_mbufs[port].m_table[ j] = m[n+j];
			j++;
		case 2:
			qconf->tx_mbufs[port].m_table[ j] = m[n+j];
			j++;
		case 1:
			qconf->tx_mbufs[port].m_table[ j] = m[n+j];
			j++;
		}
	}
	qconf->tx_mbufs[port].len = len;
}

/**
 * Send packets burst from pkts_burst to the ports in dst_port array
 */
static inline __attribute__((always_inline)) void
send_packets_multi(struct lcore_conf *qconf, struct rte_mbuf **pkts_burst,
		uint16_t dst_port[MAX_PKT_BURST], int nb_rx)
{
	int32_t k;
	int j = 0;
	/*
	 * Finish packet processing and group consecutive
	 * packets with the same destination port.
	 */
	k = RTE_ALIGN_FLOOR(nb_rx, FWDSTEP);
	
	for (j = 0; j < nb_rx; j += k) {

		int32_t m;
		uint16_t pn;

		pn = dst_port[j];
		//k = pnum[j];
        k = nb_rx;
		//  printf("j = %d   k = %d send_packetsx4 to dst_port : %d\n", j, k, pn);
		if (likely(pn != BAD_PORT))
			send_packetsx4(qconf, pn, pkts_burst + j, k);
		else
			for (m = j; m != j + k; m++)
				rte_pktmbuf_free(pkts_burst[m]);

	}
}

#endif /* _L3FWD_COMMON_H_ */
