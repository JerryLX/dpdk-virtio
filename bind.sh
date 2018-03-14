#!/bin/bash
modprobe uio
echo HISI00C2:02 > /sys/bus/platform/drivers/hns-nic/unbind
echo HISI00C2:03 > /sys/bus/platform/drivers/hns-nic/unbind
insmod ./arm64-armv8a-linuxapp-gcc/kmod/hns_uio.ko