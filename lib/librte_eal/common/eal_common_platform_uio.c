#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <rte_eal.h>
#include <rte_tailq.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_platform.h>

#include "eal_private.h"

static struct rte_tailq_elem rte_platform_uio_tailq = {
	.name = "PLATFORM_UIO_RESOURCE_LIST",
};
EAL_REGISTER_TAILQ(rte_platform_uio_tailq)

static int
platform_uio_map_secondary(struct rte_platform_device *dev)
{
	int fd, i, j;
	struct mapped_platform_resource *uio_res;
	struct mapped_platform_res_list *uio_res_list =
			RTE_TAILQ_CAST(rte_platform_uio_tailq.head, mapped_platform_res_list);


	TAILQ_FOREACH(uio_res, uio_res_list, next) {
		/* skip this element if it doesn't match our platform name */
        if(strlen(uio_res->name)!=strlen(dev->name) || 
                strncmp(uio_res->name,dev->name,strlen(uio_res->name)))
            continue;

		for (i = 0; i != uio_res->nb_maps; i++) {
			/*
			 * open devname, to mmap it
			 */
            fd = open(uio_res->maps[i].path, O_RDWR);
			if (fd < 0) {
				RTE_LOG(ERR, EAL, "Cannot open %s: %s\n",
					uio_res->maps[i].path, strerror(errno));
				return -1;
			}

			void *mapaddr = platform_map_resource(uio_res->maps[i].addr,
					fd, (off_t)uio_res->maps[i].offset,
					(size_t)uio_res->maps[i].size, 0);
			/* fd is not needed in slave process, close it */
			close(fd);
			if (mapaddr != uio_res->maps[i].addr) {
				RTE_LOG(ERR, EAL,
					"Cannot mmap device resource file %s to address: %p\n",
					uio_res->maps[i].path,
					uio_res->maps[i].addr);
				if (mapaddr != MAP_FAILED) {
					/* unmap addrs correctly mapped */
					for (j = 0; j < i; j++)
						platform_unmap_resource(
							uio_res->maps[j].addr,
							(size_t)uio_res->maps[j].size);
					/* unmap addr wrongly mapped */
					platform_unmap_resource(mapaddr,
						(size_t)uio_res->maps[i].size);
				}
				return -1;
			}
		}
		return 0;
	}

	RTE_LOG(ERR, EAL, "Cannot find resource for device\n");
	return 1;
}

/* map the platform resource of a platform device in virtual memory */
int
platform_uio_map_resource(struct rte_platform_device *dev)
{
    int i,map_idx=0, ret;
    uint64_t phaddr;
	struct mapped_platform_resource *uio_res;
	struct mapped_platform_res_list *uio_res_list =
			RTE_TAILQ_CAST(rte_platform_uio_tailq.head, mapped_platform_res_list);
    dev->intr_handle.fd = -1;
    dev->intr_handle.uio_cfg_fd = -1;
    dev->intr_handle.type = RTE_INTR_HANDLE_UNKNOWN;

    printf("enter map resource\n");
    if(rte_eal_process_type() != RTE_PROC_PRIMARY)
        return platform_uio_map_secondary(dev);

    ret = platform_uio_alloc_resource(dev, &uio_res);
    if (ret){
        printf("alloc error\n");
        return ret;
    }
	for (i = 0; i != PLATFORM_MAX_RESOURCE; i++) {
		phaddr = dev->mem_resource[i].phys_addr;
		if(!phaddr) continue;
        printf("%#lx\n", phaddr);
	} // for debug by mqc
	
	for (i = 0; i != PLATFORM_MAX_RESOURCE; i++) {
		phaddr = dev->mem_resource[i].phys_addr;
		if(!phaddr) continue;
        //printf("%#lx\n", phaddr);
        ret = platform_uio_map_resource_by_index(dev, i,
			uio_res, map_idx);
		
        if (ret){
			printf("map error name=%s map_idx=%d\n", dev->name, map_idx);
            goto error;
        }
		map_idx++;
	}

	uio_res->nb_maps = map_idx;
    
	TAILQ_INSERT_TAIL(uio_res_list, uio_res, next);

	return 0;
error:
	for (i = 0; i < map_idx; i++) {
		platform_unmap_resource(uio_res->maps[i].addr,
				(size_t)uio_res->maps[i].size);
		rte_free(uio_res->maps[i].path);
	}
	platform_uio_free_resource(dev, uio_res);
	return -1;
}


static void
platform_uio_unmap(struct mapped_platform_resource *uio_res)
{
	int i;

	if (uio_res == NULL)
		return;

	for (i = 0; i != uio_res->nb_maps; i++) {
		platform_unmap_resource(uio_res->maps[i].addr,
				(size_t)uio_res->maps[i].size);
		if (rte_eal_process_type() == RTE_PROC_PRIMARY)
			rte_free(uio_res->maps[i].path);
	}
}

static struct mapped_platform_resource *
platform_uio_find_resource(struct rte_platform_device *dev)
{
	struct mapped_platform_resource *uio_res;
	struct mapped_platform_res_list *uio_res_list =
			RTE_TAILQ_CAST(rte_platform_uio_tailq.head, mapped_platform_res_list);

	if (dev == NULL)
		return NULL;

	TAILQ_FOREACH(uio_res, uio_res_list, next) {
        uint64_t len = strlen(uio_res->name);
        if(strlen(dev->name) == len && 
                strncmp(dev->name, uio_res->name, len) == 0)
			return uio_res;
	}
	return NULL;
}

/* unmap the Platform resource of a Platform device in virtual memory */
void
platform_uio_unmap_resource(struct rte_platform_device *dev)
{
	struct mapped_platform_resource *uio_res;
	struct mapped_platform_res_list *uio_res_list =
			RTE_TAILQ_CAST(rte_platform_uio_tailq.head, mapped_platform_res_list);

	if (dev == NULL)
		return;

	/* find an entry for the device */
	uio_res = platform_uio_find_resource(dev);
	if (uio_res == NULL)
		return;

	/* secondary processes - just free maps */
	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return platform_uio_unmap(uio_res);

	TAILQ_REMOVE(uio_res_list, uio_res, next);

	/* unmap all resources */
	platform_uio_unmap(uio_res);

	/* free uio resource */
	rte_free(uio_res);

	/* close fd if in primary process */
	close(dev->intr_handle.fd);
	if (dev->intr_handle.uio_cfg_fd >= 0) {
		close(dev->intr_handle.uio_cfg_fd);
		dev->intr_handle.uio_cfg_fd = -1;
	}

	dev->intr_handle.fd = -1;
	dev->intr_handle.type = RTE_INTR_HANDLE_UNKNOWN;
}
