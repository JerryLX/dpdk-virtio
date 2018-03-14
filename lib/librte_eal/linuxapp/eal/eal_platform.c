
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <rte_log.h>
#include <rte_platform.h>
#include <rte_pci_platform.h>
#include <rte_eal_memconfig.h>
#include <rte_malloc.h>
#include <rte_devargs.h>
#include <rte_memcpy.h>
#include <sys/stat.h>
#include <rte_bus.h>

#include "eal_filesystem.h"
#include "eal_private.h"
#include "eal_platform_init.h"

extern struct rte_platform_bus rte_platform_bus;

static int
platform_get_kernel_driver_by_path(const char *filename, char *dri_name)
{
	int count;
	char path[PATH_MAX];
	char *name;

	if (!filename || !dri_name)
		return -1;

	count = readlink(filename, path, PATH_MAX);
	if (count >= PATH_MAX)
		return -1;

	/* For device does not have a driver */
	if (count < 0){
//		RTE_LOG(INFO, EAL, "there is no driver in %s\n", filename);
        return 1;
    }

	path[count] = '\0';

	name = strrchr(path, '/');
	if (name) {
		strncpy(dri_name, name + 1, strlen(name + 1) + 1);
		return 0;
	}

    return -1;
}

/* 
 * unbind kernel driver for this device 
 * by lixu
 */
int
platform_unbind_kernel_driver(struct rte_platform_device *dev)
{
	int n;
	FILE *f;
	char filename[PATH_MAX];
	char buf[BUFSIZ];
    char *name = dev->name;

	/* open /sys/bus/platform/devices/devname/driver */
	snprintf(filename, sizeof(filename),
		"%s/%s/driver/unbind", platform_get_sysfs_path(),
		name);

	f = fopen(filename, "w");
	if (f == NULL) /* device was not bound */
		return 0;

	n = snprintf(buf, sizeof(buf), "%s\n",
	             name);
	if ((n < 0) || (n >= (int)sizeof(buf))) {
		goto error;
	}
	if (fwrite(buf, n, 1, f) == 0) {
		RTE_LOG(ERR, EAL, "%s(): could not write to %s\n", __func__,
				filename);
		goto error;
	}

	fclose(f);
	return 0;

error:
	fclose(f);
	return -1;
}

/* Map platform device */
int
rte_platform_map_device(struct rte_platform_device *dev)
{
    int ret = -1;
	switch (dev->kdrv) {
    case RTE_KDRV_HNS_UIO:
    case RTE_KDRV_PLF_UIO:
        
        ret = platform_uio_map_resource(dev);
        break;
    default:
		RTE_LOG(DEBUG, EAL,
			"  Not managed by a supported kernel driver, skipped\n");
		ret = 1;
		break;
    }
    return ret;
}

/* Unmap platform device */
void
rte_platform_unmap_device(struct rte_platform_device *dev)
{
	switch (dev->kdrv) {
    case RTE_KDRV_HNS_UIO:
    case RTE_KDRV_PLF_UIO:
        platform_uio_unmap_resource(dev);
        break;
    default:
		RTE_LOG(DEBUG, EAL,
			"  Not managed by a supported kernel driver, skipped\n");
		break;
    }
	return;
}


static int
platform_uio_parse_one_map(struct rte_platform_device *dev,
        int index, const char *parent_dirname)
{
    int addr_fd, size_fd;
    char addr_name[PATH_MAX];
    char size_name[PATH_MAX];
    char addr_buf[32], size_buf[32];
    uint64_t uio_addr, uio_size;

    //RTE_LOG(DEBUG,EAL, "parsing one map: %s\n", parent_dirname);
    
    snprintf(addr_name, sizeof(addr_name), "%s/%s", parent_dirname, "addr");
    snprintf(size_name, sizeof(addr_name), "%s/%s", parent_dirname, "size");

    addr_fd = open(addr_name, O_RDONLY);
    if(!addr_fd || !read(addr_fd, addr_buf, sizeof(addr_buf))){
        RTE_LOG(ERR, EAL, "open dir %s failed!\n", addr_name);
        return -1;
    }
    uio_addr = (uint64_t)strtoull(addr_buf, NULL, 0);
    close(addr_fd);

    size_fd = open(size_name, O_RDONLY);
    if(!size_fd || !read(size_fd, size_buf, sizeof(size_buf))){
        RTE_LOG(ERR, EAL, "open dir %s failed!\n", size_name);
        return -1;
    }
    uio_size = (uint64_t)strtol(size_buf, NULL, 0);
    close(size_fd);
    dev->mem_resource[index].phys_addr = uio_addr;
    dev->mem_resource[index].len = uio_size;
    
    //RTE_LOG(DEBUG, EAL, "parsing map, index: %d, phaddr: %lx, size: %lu\n", 
    //        index,uio_addr,uio_size);
    
    return 0;
}

static int
platform_uio_parse_map(struct rte_platform_device *dev,
        const char *filename)
{
    char dirname[PATH_MAX]; /* contains the /.../maps */
    char child_dir[PATH_MAX];
    int index = 0;
    
    struct dirent **namelist;
    int n,i;

    snprintf(dirname, sizeof(dirname), "%s/%s", filename, "maps");

    n = scandir(dirname,&namelist,NULL,alphasort);
    if(n == -1) {
        RTE_LOG(ERR, EAL, "open dir %s failed!\n", dirname);
        return -1;
    }
    for(i=0;i<n;i++){
        if (strncmp(namelist[i]->d_name, "map", 3) != 0)
            continue;
        snprintf(child_dir, sizeof(child_dir), "%s/%s", dirname, namelist[i]->d_name);
        if(platform_uio_parse_one_map(dev,index,child_dir))
            return -1;
        index++;
        free(namelist[i]);
    }

    return 0;
}

/* Scan one platform sysfs entry, and fill the devices list from it. */
static int
platform_scan_one(const char *dirname, const char *dev_name, int uio_num)
{
	char filename[PATH_MAX];
//	unsigned long tmp;
	struct rte_platform_device *dev;
	char driver[PATH_MAX];
	int ret, len;

	dev = malloc(sizeof(*dev));
	if (dev == NULL)
		return -1;

	memset(dev, 0, sizeof(*dev));

    len = strlen(dev_name)+1;
    dev->name = malloc(len+1);
    memset(dev->name,0,len);
    snprintf(dev->name, len, "%s", dev_name);

    //set uio_num
    dev->uio_num = uio_num;
    snprintf(filename, sizeof(filename), "%s/uio/uio%u", 
            dirname, uio_num);
    
    if(platform_uio_parse_map(dev, filename))
    {
        RTE_LOG(ERR, EAL, "parse map error!\n");
        return -1;
    }

	/* parse driver */
	snprintf(filename, sizeof(filename), "%s/driver", dirname);
    ret = platform_get_kernel_driver_by_path(filename, driver);
    if (ret < 0) {
		RTE_LOG(ERR, EAL, "Fail to get kernel driver\n");
		free(dev);
		return -1;
	}
    //RTE_LOG(INFO, EAL, "%s has driver: %s\n", dev_name, driver);

	if (!ret) {
		if (!strcmp(driver, "hns_uio"))
			dev->kdrv = RTE_KDRV_HNS_UIO;
		else if(!strcmp(driver, "plf_uio"))
			dev->kdrv = RTE_KDRV_PLF_UIO;
        else{
            dev->kdrv = RTE_KDRV_UNKNOWN;
        }
    }
    else
       dev->kdrv = RTE_KDRV_NONE;

	/* device is valid, add in list (sorted) */
	if (TAILQ_EMPTY(&rte_platform_bus.device_list)) {
		TAILQ_INSERT_TAIL(&rte_platform_bus.device_list, dev, next);
	} else {
		struct rte_platform_device *dev2;
		int ret;

		TAILQ_FOREACH(dev2, &rte_platform_bus.device_list, next) {
			ret = rte_eal_compare_platform_name(dev, dev2);
			if (ret != 0)
				continue;

			else { /* already registered */
              RTE_LOG(INFO, EAL, "%s already registered, %s\n", dev_name, dev2->name);
				memmove(dev2->mem_resource, dev->mem_resource,
					sizeof(dev->mem_resource));
				free(dev);
			    return 0;
			}
		}
        
		TAILQ_INSERT_TAIL(&rte_platform_bus.device_list, dev, next);
	}

	return 0;
}

static int
platform_scan_uio(const char *dirname, const char *dev_name)
{
    char filename[PATH_MAX];
    DIR *dir;
    struct dirent *e;
    int ret = 0;
    int uio_num;

    snprintf(filename, sizeof(filename), "%s/uio", dirname);
    dir = opendir(filename);
    
    //no uio device in this platform device
    //ignore this platform device
    if(dir == NULL)
        return 0;

	/* take the first file starting with "uio" */
	while ((e = readdir(dir)) != NULL) {
		/* format uio%d ...*/
		int shortprefix_len = sizeof("uio") - 1;
		char *endptr;

		if (strncmp(e->d_name, "uio", 3) != 0)
			continue;

		uio_num = strtoull(e->d_name + shortprefix_len, &endptr, 10);
		if ( endptr != (e->d_name + shortprefix_len)) {
            ret = platform_scan_one(dirname, dev_name, uio_num);
            if(ret){
                RTE_LOG(ERR, EAL, "scan one failed!, err code: %d\n", ret);
                return ret;
            }
        }

	}
	closedir(dir);
    return 0;
}

void *
platform_find_max_end_va(void)
{
	const struct rte_memseg *seg = rte_eal_get_physmem_layout();
	const struct rte_memseg *last = seg;
	unsigned i = 0;

	for (i = 0; i < RTE_MAX_MEMSEG; i++, seg++) {
		if (seg->addr == NULL)
			break;

		if (seg->addr > last->addr)
			last = seg;

	}
	return RTE_PTR_ADD(last->addr, last->len);
}

/*
 * Scan the content of the platform bus, and the devices in the devices
 * list
 *
 * by lixu
 */
int 
rte_platform_scan(void)
{
	struct dirent *e;
	DIR *dir;
	char dirname[PATH_MAX];
    char devname[PATH_MAX];

	dir = opendir(platform_get_sysfs_path());
	if (dir == NULL) {
		RTE_LOG(ERR, EAL, "%s(): opendir failed: %s\n",
			__func__, strerror(errno));
		return -1;
	}

	while ((e = readdir(dir)) != NULL) {
		if (e->d_name[0] == '.')
			continue;

		snprintf(dirname, sizeof(dirname), "%s/%s",
				platform_get_sysfs_path(), e->d_name);

        snprintf(devname, sizeof(devname), "%s", e->d_name);

	    //RTE_LOG(INFO, EAL, "scanning dir %s\n", dirname);	
        if (platform_scan_uio(dirname, devname) < 0)
			goto error;
	}
	closedir(dir);
	return 0;

error:
    closedir(dir);
    return -1;
}



