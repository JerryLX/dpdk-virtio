/**
 * Like eal_pci_uio.c. 
 * Alloc UIO resource for platform device.
 *
 * @author lixu
 */
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <rte_log.h>
#include <rte_platform.h>
#include <rte_pci_platform.h>
#include <rte_eal_memconfig.h>
#include <rte_common.h>
#include <rte_malloc.h>

#include "eal_platform_init.h"
#include "eal_filesystem.h"

void *platform_map_addr = NULL;

/**
 * hns_uio has already create char dev(nic_uio) 
 *
 */
//static int
//platform_mknod_uio_dev(const char *sysfs_uio_path, unsigned uio_num)
//{
//	FILE *f;
//	char filename[PATH_MAX];
//	int ret;
//	unsigned major, minor;
//	dev_t dev;
//
//	/* get the name of the sysfs file that contains the major and minor
//	 * of the uio device and read its content */
//	snprintf(filename, sizeof(filename), "%s/dev", sysfs_uio_path);
//
//	f = fopen(filename, "r");
//	if (f == NULL) {
//		RTE_LOG(ERR, EAL, "%s(): cannot open sysfs to get major:minor\n",
//			__func__);
//		return -1;
//	}
//
//	ret = fscanf(f, "%u:%u", &major, &minor);
//	if (ret != 2) {
//		RTE_LOG(ERR, EAL, "%s(): cannot parse sysfs to get major:minor\n",
//			__func__);
//		fclose(f);
//		return -1;
//	}
//	fclose(f);
//
//	/* create the char device "mknod /dev/uioX c major minor" */
//	snprintf(filename, sizeof(filename), "/dev/uio%u", uio_num);
//	dev = makedev(major, minor);
//	ret = mknod(filename, S_IFCHR | S_IRUSR | S_IWUSR, dev);
//	if (f == NULL) {
//		RTE_LOG(ERR, EAL, "%s(): mknod() failed %s\n",
//			__func__, strerror(errno));
//		return -1;
//	}
//
//	return ret;
//}

/*
 * Return the uioX char device used for a platform device.
 * On success, return the UIO number.
 */
//static int
//platform_get_uio_dev(struct rte_platform_device *dev, char *dstbuf,
//        unsigned int buflen, int create)
//{
//    unsigned int uio_num;
//    struct dirent *e;
//    DIR *dir;
//    char dirname[PATH_MAX];
//
//    snprintf(dirname, sizeof(dirname),
//            "%s/%s/uio",platform_get_sysfs_path(),
//            dev->name);
//
//    /* need to fullfill */
//	dir = opendir(dirname);
//	if (dir == NULL) {
//		/* retry with the parent directory */
//		snprintf(dirname, sizeof(dirname),
//				"%s/%s", platform_get_sysfs_path(),
//				dev->name);
//		dir = opendir(dirname);
//
//		if (dir == NULL) {
//			RTE_LOG(ERR, EAL, "Cannot opendir %s\n", dirname);
//			return -1;
//		}
//	}
//
//	/* take the first file starting with "uio" */
//	while ((e = readdir(dir)) != NULL) {
//		/* format could be uio%d ...*/
//		int shortprefix_len = sizeof("uio") - 1;
//		/* ... or uio:uio%d */
//		int longprefix_len = sizeof("uio:uio") - 1;
//		char *endptr;
//
//		if (strncmp(e->d_name, "uio", 3) != 0)
//			continue;
//
//		/* first try uio%d */
//		errno = 0;
//		uio_num = strtoull(e->d_name + shortprefix_len, &endptr, 10);
//		if (errno == 0 && endptr != (e->d_name + shortprefix_len)) {
//			snprintf(dstbuf, buflen, "%s/uio%u", dirname, uio_num);
//			break;
//		}
//
//		/* then try uio:uio%d */
//		errno = 0;
//		uio_num = strtoull(e->d_name + longprefix_len, &endptr, 10);
//		if (errno == 0 && endptr != (e->d_name + longprefix_len)) {
//			snprintf(dstbuf, buflen, "%s/uio:uio%u", dirname, uio_num);
//			break;
//		}
//	}
//	closedir(dir);
//
//	/* No uio resource found */
//	if (e == NULL)
//		return -1;
//
//	/* create uio device if we've been asked to */
//	if (internal_config.create_uio_dev && create &&
//			platform_mknod_uio_dev(dstbuf, uio_num) < 0)
//		RTE_LOG(WARNING, EAL, "Cannot create /dev/uio%u\n", uio_num);
//
//    return uio_num;
//}

/*
 * Free uio resource for platform device.
 */
void
platform_uio_free_resource(struct rte_platform_device *dev,
        struct mapped_platform_resource *uio_res)
{
    rte_free(uio_res);
/*
    if(dev->intr_handle.uio_cfg_fd >= 0) {
        close(dev->intr_handle.uio_cfg_fd);
        dev->intr_handle.uio_cfg_fd = -1;
    }
*/
	if (dev->intr_handle.fd) {
		close(dev->intr_handle.fd);
		dev->intr_handle.fd = -1;
		dev->intr_handle.type = RTE_INTR_HANDLE_UNKNOWN;
	} 
}

//static int
//platform_uio_parse_one_map(struct rte_platform_device *dev,
//        int index, const char *parent_dirname)
//{
//    int addr_fd, size_fd;
//    char addr_name[PATH_MAX];
//    char size_name[PATH_MAX];
//    char addr_buf[32], size_buf[32];
//    uint64_t uio_addr, uio_size;
//
//    snprintf(addr_name, sizeof(addr_name), "%s/%s", parent_dirname, "addr");
//    snprintf(size_name, sizeof(addr_name), "%s/%s", parent_dirname, "size");
//
//    addr_fd = open(addr_name, O_RDONLY);
//    if(!addr_fd || !read(addr_fd, addr_buf, sizeof(addr_buf))){
//        RTE_LOG(ERR, EAL, "open dir %s failed!\n", addr_name);
//        return -1;
//    }
//    uio_addr = (uint64_t)strtoull(addr_buf, NULL, 0);
//    close(addr_fd);
//
//    size_fd = open(addr_name, O_RDONLY);
//    if(!size_fd || !read(size_fd, size_buf, sizeof(size_buf))){
//        RTE_LOG(ERR, EAL, "open dir %s failed!\n", size_name);
//        return -1;
//    }
//    uio_size = (uint64_t)strtol(size_buf, NULL, 0);
//    close(size_fd);
//    dev->mem_resource[index].phys_addr = uio_addr;
//    dev->mem_resource[index].len = uio_size;
//    return 0;
//}
//
//static int
//platform_uio_parse_map(struct rte_platform_device *dev,
//        const char *filename)
//{
//    char dirname[PATH_MAX]; /* contains the /dev/uioX/maps */
//    DIR *dir;
//    struct dirent *file;
//    int index = 0;
//    
//    snprintf(dirname, sizeof(dirname), "%s/%s", filename, "maps");
//    
//    dir = opendir(dirname);
//    if(!dir) {
//        RTE_LOG(ERR, EAL, "open dir %s failed!\n", dirname);
//        return -1;
//    }
//
//    while ((file = readdir(dir))!=NULL){
//        if (strncmp(file->d_name, "map", 3) != 0)
//            continue;
//        if(!platform_uio_parse_one_map(dev,index,dirname))
//            return -1;
//        index++;
//    }
//    return 0;
//}

/*
 * Alloc uio resource for platform device.
 */
int
platform_uio_alloc_resource(struct rte_platform_device *dev,
        struct mapped_platform_resource **uio_res)
{
    char devname[PATH_MAX]; /* contains the /dev/uioX */
    int uio_num;
    /* find uio resource */
    uio_num = dev->uio_num;
    if(uio_num < 0){
        RTE_LOG(WARNING, EAL, "platform dev %s not managed by UIO driver, "
                "skipping\n", dev->name);
        return 1;
    }
    snprintf(devname, sizeof(devname), "/dev/uio%u", uio_num);

    /* save fd if in primary process */
    dev->intr_handle.fd = open(devname, O_RDWR);
    if (dev->intr_handle.fd < 0){
        RTE_LOG(ERR, EAL, "Cannot open %s\n",devname);
        goto error;
    }

    /*
    if(platform_uio_parse_map(dev, devname))
    {
        RTE_LOG(ERR, EAL, "parse map error!\n");
        goto error;
    }
    */
    /* this platform device has no config */
    /*
    snprintf(cfgname, sizeof(cfgname),
        "/sys/class/uio/uio%u/device/config", uio_num);
    dev->intr_handle.uio_cfg_fd = open(cfgname, O_RDWR);
    if(dev->intr_handle.uio_cfg_fd < 0){
        RTE_LOG(ERR, EAL, "Cannot open %s\n", cfgname);
        goto error;
    }
    */

    if (dev->kdrv == RTE_KDRV_HNS_UIO || dev->kdrv == RTE_KDRV_PLF_UIO)
        dev->intr_handle.type = RTE_INTR_HANDLE_UIO;
    else{
        RTE_LOG(ERR, EAL, "not implement yet\n");
        goto error;
    }

    /* allocate the mapping details for secondary processes */
    *uio_res = rte_zmalloc("UIO_RES", sizeof(**uio_res), 0);
    if(*uio_res == NULL){
        RTE_LOG(ERR, EAL,
                "%s(): cannot store uio map details\n", __func__);
        goto error;
    }

    snprintf((*uio_res)->path, sizeof((*uio_res)->path), "%s", devname);
    memcpy((*uio_res)->name, dev->name, sizeof((*uio_res)->name));
    strcpy((*uio_res)->name, dev->name);
    return 0;
error:
    platform_uio_free_resource(dev, *uio_res);
    return -1;
}

int
platform_uio_map_resource_by_index(struct rte_platform_device *dev, int res_idx,
		struct mapped_platform_resource *uio_res, int map_idx)
{
	int fd;
	char devname[PATH_MAX];
	void *mapaddr;
	struct platform_map *maps;

	maps = uio_res->maps;

	/* update devname for mmap  */
	snprintf(devname, sizeof(devname),
			"/dev/uio%d",
			dev->uio_num);

	/* allocate memory to keep path */
	maps[map_idx].path = rte_malloc(NULL, strlen(devname) + 1, 0);
	if (maps[map_idx].path == NULL) {
		RTE_LOG(ERR, EAL, "Cannot allocate memory for path: %s\n",
				strerror(errno));
		return -1;
	}

	/*
	 * open resource file, to mmap it
	 */
	fd = open(devname, O_RDWR);
	if (fd < 0) {
		RTE_LOG(ERR, EAL, "Cannot open %s: %s\n",
				devname, strerror(errno));
		goto error;
	}

	/* try mapping somewhere close to the end of hugepages */
	if (platform_map_addr == NULL)
		platform_map_addr = platform_find_max_end_va();

	
	//printf("%p\n", platform_map_addr);
	
   //    mapaddr = platform_map_resource(platform_map_addr, fd, uio_res->offset*getpagesize(),
   //   		(size_t)dev->mem_resource[res_idx].len, 0);
    //   uio_res->offset+=(dev->mem_resource[res_idx].len+getpagesize()-1)/getpagesize();
 unsigned long size2 = dev->mem_resource[res_idx].len + getpagesize() - 1;
 size2 = size2 / getpagesize() * getpagesize();  
 platform_map_addr = NULL;    
 mapaddr = platform_map_resource(platform_map_addr, fd, map_idx*getpagesize(),
      		(size_t)size2, 0);
        printf("res_idx = %d", res_idx); 
    //	mapaddr = (void *)mmap(NULL, (size_t)dev->mem_resource[res_idx].len,
      //                     PROT_READ|PROT_WRITE,MAP_SHARED,fd, 7*map_idx*getpagesize());
    close(fd);
	if (mapaddr == MAP_FAILED)
	{
		printf("mapaddr = MAP_FAILED\n");
		goto error;
    }
	platform_map_addr = RTE_PTR_ADD(mapaddr,
			(size_t)dev->mem_resource[res_idx].len);

	maps[map_idx].phaddr = dev->mem_resource[res_idx].phys_addr;
	maps[map_idx].size = dev->mem_resource[res_idx].len;
	maps[map_idx].addr = mapaddr;
	maps[map_idx].offset = map_idx*getpagesize();
	printf("idx:%d,%p, mapped addr:%p\n",map_idx,(void *)(dev->mem_resource[res_idx].phys_addr),mapaddr);
    strcpy(maps[map_idx].path, devname);
	dev->mem_resource[res_idx].addr = mapaddr;
	return 0;

error:
	rte_free(maps[map_idx].path);
	return -1;
}
