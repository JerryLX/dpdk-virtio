#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

__visible struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x2d063fe6, __VMLINUX_SYMBOL_STR(module_layout) },
	{ 0x2d63e7a8, __VMLINUX_SYMBOL_STR(platform_driver_unregister) },
	{ 0xae12b1a4, __VMLINUX_SYMBOL_STR(__platform_driver_register) },
	{ 0x45a55ec8, __VMLINUX_SYMBOL_STR(__iounmap) },
	{ 0x8cf07976, __VMLINUX_SYMBOL_STR(__uio_register_device) },
	{ 0x5e255ad7, __VMLINUX_SYMBOL_STR(devm_ioremap) },
	{ 0x25cd0484, __VMLINUX_SYMBOL_STR(platform_get_resource) },
	{ 0x1c40d6, __VMLINUX_SYMBOL_STR(device_create) },
	{ 0x2cb17f48, __VMLINUX_SYMBOL_STR(__class_create) },
	{ 0x19297c53, __VMLINUX_SYMBOL_STR(__register_chrdev) },
	{ 0xd6b8e852, __VMLINUX_SYMBOL_STR(request_threaded_irq) },
	{ 0xd32cf44d, __VMLINUX_SYMBOL_STR(platform_get_irq) },
	{ 0x13435c, __VMLINUX_SYMBOL_STR(kmem_cache_alloc_trace) },
	{ 0xca1bb766, __VMLINUX_SYMBOL_STR(kmalloc_caches) },
	{ 0x37a0cba, __VMLINUX_SYMBOL_STR(kfree) },
	{ 0x6bc3fbc0, __VMLINUX_SYMBOL_STR(__unregister_chrdev) },
	{ 0x95152caa, __VMLINUX_SYMBOL_STR(uio_unregister_device) },
	{ 0x30bb47be, __VMLINUX_SYMBOL_STR(class_destroy) },
	{ 0x28318305, __VMLINUX_SYMBOL_STR(snprintf) },
	{ 0x27e1a049, __VMLINUX_SYMBOL_STR(printk) },
	{ 0x119ef07c, __VMLINUX_SYMBOL_STR(remap_pfn_range) },
	{ 0x1fdc7df2, __VMLINUX_SYMBOL_STR(_mcount) },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=uio";

MODULE_ALIAS("of:N*T*Cvirtio,mmio*");
