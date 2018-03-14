/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2015 Intel Corporation. All rights reserved.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ip.h>

#define RX_RING_SIZE 128
#define TX_RING_SIZE 512

#define NUM_MBUFS 32768
#define MBUF_CACHE_SIZE 256
#define BURST_SIZE 32
#define REORDER_BUFFER_SIZE 8192
static uint64_t timer_period = 100000000;
#define nTEST_CORE 6
#define nQUEUE 16


static const struct rte_eth_conf port_conf_default = {
	.rxmode = { .max_rx_pkt_len = ETHER_MAX_LEN, },
};

static unsigned nb_ports;
/*
 * Initialises a given port using global settings and with the rx buffers
 * coming from the mbuf_pool passed as parameter
 */
static inline int
port_init(uint8_t port, struct rte_mempool *mbuf_pool)
{
	struct rte_eth_conf port_conf = port_conf_default;
	const uint16_t rx_rings = 16, tx_rings = 16;
	int retval;
	uint16_t q;

	if (port >= rte_eth_dev_count())
		return -1;


    printf("init port: %d\n", port);
    retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;
    //printf("rx_queue_setup\n");
	for (q = 0; q < rx_rings; q++) {
		printf("q=%d\n", q); 
		retval = rte_eth_rx_queue_setup(port, q, RX_RING_SIZE,
				rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		//printf("ret=%d\n", retval);
		if (retval < 0)
			return retval;
	}
	//printf("tx_queue_setup\n");
	for (q = 0; q < tx_rings; q++) {
		//printf("q=%d  ",q);
		retval = rte_eth_tx_queue_setup(port, q, TX_RING_SIZE,
				rte_eth_dev_socket_id(port), NULL);
		//printf("retval=%d\n", retval);
		if (retval < 0)
			return retval;
	}
    printf("rte_eth_dev_start\n");
	retval  = rte_eth_dev_start(port);	
	printf("retval=%d\n", retval);
    if (retval < 0)
		return retval;
    printf("after start port\n");
    
	struct ether_addr addr;

	rte_eth_macaddr_get(port, &addr);
	printf("Port %u MAC: %02"PRIx8" %02"PRIx8" %02"PRIx8
			" %02"PRIx8" %02"PRIx8" %02"PRIx8"\n",
			(unsigned)port,
			addr.addr_bytes[0], addr.addr_bytes[1],
			addr.addr_bytes[2], addr.addr_bytes[3],
			addr.addr_bytes[4], addr.addr_bytes[5]);

	rte_eth_promiscuous_enable(port);

	return 0;
}


static void lcore_main(void)
{
	uint8_t port = 1;
    uint8_t qid;
    uint64_t cur_tsc, prev_tsc;
    uint64_t count[16][10];
	uint64_t count_tx[16][10];
	uint16_t nb_rx = 0, nb_tx = 0;
	struct rte_mbuf *bufs[BURST_SIZE];
    int k;
	//int test_port = 8;
    (void)k;
	uint32_t enabled_port_mask;
	printf("please input the port_mask: ");
	k = scanf("%x", &enabled_port_mask);
    for(qid=0;qid<16;qid++) {
		for(port=0;port<10;port++)
        count[qid][port]=0;
    }
    for(qid=0;qid<16;qid++) {
		for(port=0;port<10;port++)
        count_tx[qid][port]=0;
    }

    prev_tsc = 0;
	printf("\nCore %u forwarding packets. [Ctrl+C to quit]\n",
			rte_lcore_id());
	 for(;;){
        cur_tsc = rte_rdtsc();
        if(unlikely(cur_tsc-prev_tsc>timer_period)){
            prev_tsc = cur_tsc;
            for(int i=0;i<10;i++){
                printf("port %d rx:",i);
				for(qid=0;qid<16;qid++)
					printf("%llu ",(unsigned long long)count[qid][i]);
				printf("\n");
				printf("port %d tx:",i);
				for(qid=0;qid<16;qid++)
					printf("%llu ",(unsigned long long)count_tx[qid][i]);
				printf("\n");
            }
            printf("=====================================\n");
        }
        for(port=0;port<10;port++){
		if ((enabled_port_mask & (1 << port)) == 0) {
			continue;
	 	}       
		for (qid = 0 ; qid < 16; qid++){
                nb_rx = rte_eth_rx_burst(port, qid,
           			bufs, BURST_SIZE);
           	    count[qid][port] += nb_rx;
                if(nb_rx == 0) continue;
			 	
                nb_tx = rte_eth_tx_burst(port,qid ,bufs, nb_rx);

				count_tx[qid][port] += nb_tx;
                if(unlikely(nb_tx<nb_rx)){
                    uint16_t buf = nb_tx;
                    for(;buf<nb_rx;buf++){
                        rte_pktmbuf_free(bufs[buf]);
                    }
                }
            }
        }
		
	 }
}
/*
static int
launch_one_lcore(__attribute__((unused)) void *dummy)
{
	lcore_main();
	return 0;
}
*/


/* Main function, does initialisation and calls the per-lcore functions */
int
main(int argc, char *argv[])
{
	struct rte_mempool *mbuf_pool;
	uint8_t portid;

	/* init EAL */
	int ret = rte_eal_init(argc, argv);

	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
	argc -= ret;
	argv += ret;

    
	nb_ports = rte_eth_dev_count();
    printf("num of ports: %d\n", nb_ports);
	

    
	
	
	if (nb_ports < 2 || (nb_ports & 1))
		rte_exit(EXIT_FAILURE, "Error: number of ports must be even\n");

	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL",
		NUM_MBUFS * nb_ports, MBUF_CACHE_SIZE, 0,
		RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	/* initialize all ports */
	for (portid = 0; portid < nb_ports; portid++)
		if (port_init(portid, mbuf_pool) != 0)
			rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu8"\n",
					portid);

    printf("after port init\n");

	if (rte_lcore_count() < nTEST_CORE)
		rte_exit(EXIT_FAILURE, "%d core is needed!\n", nTEST_CORE);
	
    /* call lcore_main on each core */
	

    lcore_main();

	return 0;
}
