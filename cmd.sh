modprobe uio
echo a003a00.virtio_mmio > /sys/bus/platform/drivers/virtio-mmio/unbind
echo a003c00.virtio_mmio > /sys/bus/platform/drivers/virtio-mmio/unbind
insmod /root/dpdk-virtio/arm64-virtio-linuxapp-gcc/kmod/plf_uio.ko
./usertools/dpdk-setup.sh
