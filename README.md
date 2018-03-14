# DPDK-Part2

**What is DPDK?**

DPDK is a set of libraries and drivers for fast packet processing.
It supports many processor architectures and both FreeBSD and Linux.

The DPDK uses the Open Source BSD license for the core libraries and
drivers. The kernel components are GPLv2 licensed.

Please check the doc directory for release notes,
API documentation, and sample application information.

For questions and usage discussions, subscribe to: users@dpdk.org
Report bugs and issues to the development mailing list: dev@dpdk.org

**What is DPDK-Part2?**

The goal of DPDK-Part2 is to optimize DPDK-Part1 in the case of simultaneous forwarding of ten NICs.


## TODO:

**Merge DPDK-part1 with DPDK 17.05**

1.	Configure ARM D05 —— *DONE*
2.	Download DPDK 17.05 —— *DONE*
3.	Merge DPDK-Part1 on DPDK 17.05

**NIC forwarding performance tests and optimizations**
1.	Construct testbed with 10 NICs(6 SoC NICs and 4 82599 NICs)
	+ hash-l3fwd
	+ lpm-l3fwd
2.	Test baseline performance
3.	Optimize performance by 50%

**VHOST optimization**
1.	Use Virtio vitualization on the host and run l2fwd on the guest. 
2.	The performance of the process in each VM reaches 3.5mpps.

**IPSEC module acceleration**
1.	Enable IPSEC module
2.	Test performance with 10 NICs

**IPSEC optimization**
1.	The performance of the process reaches 2mpps.
2.	Enable multi-process encryption/decryption simultaneously.



