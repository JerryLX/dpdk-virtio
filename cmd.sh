modprobe uio
echo a003c00.virtio_mmio > /sys/bus/platform/drivers/virtio-mmio/unbind
insmod /root/dpdk-part2@guest/arm64-virtio-linuxapp-gcc/kmod/plf_uio.ko
