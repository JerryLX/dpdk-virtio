#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <errno.h>
#include <sys/queue.h>

#include <rte_log.h>
#include <rte_branch_prediction.h>
#include <rte_common.h>
#include <rte_memory.h>        /* for definition of RTE_CACHE_LINE_SIZE */
#include <rte_malloc.h>
#include <rte_memzone.h>
#include <rte_eal.h>
#include <rte_eal_memconfig.h>
#include <rte_per_lcore.h>
#include <rte_string_fns.h>
#include <rte_errno.h>
#include <rte_rwlock.h>
#include <rte_spinlock.h>


#include "rte_trie.h"

TAILQ_HEAD(rte_trie_list, rte_tailq_entry);

static struct rte_tailq_elem rte_trie_tailq = {
	.name = "RTE_TRIE",
};
EAL_REGISTER_TAILQ(rte_trie_tailq)

enum valid_flag {
	INVALID = 0,
	VALID
};

static uint32_t __attribute__((pure))
depth_to_mask(uint8_t depth)
{
	/* To calculate a mask start with a 1 on the left hand side and right
	 * shift while populating the left hand side with 1's
	 */
	return (int)0x80000000 >> (depth - 1);
}


static inline uint32_t __attribute__((pure))
depth_to_range(uint8_t depth)
{
	/*
	 * Calculate range. (Note: 2^depth = 1 << depth)
	 */
	if (depth <= 8)
		return 1 << (8 - depth);

	/* Else if depth is greater than 8 */
	return 1 << (8 - depth);
}



struct rte_trie *
rte_trie_create(const char *name, int socket_id)
{
	char mem_name[RTE_LPM_NAMESIZE];
	struct rte_trie *trie = NULL;
	struct rte_tailq_entry *te;
	uint32_t mem_size;
	struct rte_trie_list *lpm_list;
	lpm_list = RTE_TAILQ_CAST(rte_trie_tailq.head, rte_trie_list);

	//RTE_BUILD_BUG_ON(sizeof(struct rte_lpm_tbl_entry) != 4);

	/* Check user arguments. */
	if ((name == NULL) || (socket_id < -1)) {
		rte_errno = EINVAL;
		return NULL;
	}

	snprintf(mem_name, sizeof(mem_name), "TRIE_%s", name);

	/* Determine the amount of memory to allocate. */
	mem_size = sizeof(*trie);
	rte_rwlock_write_lock(RTE_EAL_TAILQ_RWLOCK);

	/* guarantee there's no existing */
	TAILQ_FOREACH(te, lpm_list, next) {
		trie = (struct rte_trie *) te->data;
		if (strncmp(name, trie->name, RTE_LPM_NAMESIZE) == 0)
			break;
	}
	trie = NULL;
	if (te != NULL) {
		rte_errno = EEXIST;
		goto exit;
	}

	/* allocate tailq entry */
	te = rte_zmalloc("TRIE_TAILQ_ENTRY", sizeof(*te), 0);
	if (te == NULL) {
		RTE_LOG(ERR, LPM, "Failed to allocate tailq entry\n");
		goto exit;
	}

	/* Allocate memory to store the LPM data structures. */
	trie = (struct rte_trie *)rte_zmalloc_socket(mem_name, mem_size,
			RTE_CACHE_LINE_SIZE, socket_id);
	if (trie == NULL) {
		RTE_LOG(ERR, LPM, "LPM memory allocation failed\n");
		rte_free(te);
		goto exit;
	}
	trie->trie_node = (struct rte_trie_node *)rte_zmalloc_socket("TRIE_NODE", sizeof(struct rte_trie_node)*RTE_NODE_NUM*RTE_LPM_GROUP_MAX_NUM +1,
			RTE_CACHE_LINE_SIZE, socket_id);
	
	if (trie->trie_node == NULL) {
		RTE_LOG(ERR, LPM, "LPM trie_node memory allocation failed\n");
		rte_free(trie);
		trie = NULL;
		rte_free(te);
		goto exit;
	}
	trie->current_group = trie->trie_node +1;
	/* Save user arguments. */
	snprintf(trie->name, sizeof(trie->name), "%s", name);

	te->data = (void *) trie;

	TAILQ_INSERT_TAIL(lpm_list, te, next);

exit:
	rte_rwlock_write_unlock(RTE_EAL_TAILQ_RWLOCK);

	return trie;
}

static inline int
rte_trie_add_help(struct rte_trie_node *node,uint8_t index, uint8_t depth, uint32_t next_hop){
	if(node ==NULL)
		return -EINVAL;
	uint8_t last_index, i;
	last_index = index+ depth_to_range(depth);
	for(i=index;i<last_index;i++){
		if(depth> node->depth){
			node->valid = VALID;
			node->next_hop = next_hop;
			node->depth = depth;
		}
		node++;
	}
	return 0;
}



int
rte_trie_add(struct rte_trie *trie, uint32_t ip, uint8_t depth, uint32_t next_hop)
{
	struct rte_trie_node *node;
	struct rte_trie_node * end_node;
	
	uint32_t ip_mask;
	uint8_t index;
	if((trie == NULL) || (depth<1) || (depth > RTE_TRIE_MAX_DEPTH))
		return -EINVAL;

	node = trie->trie_node;
	end_node = trie->current_group + RTE_NODE_NUM *RTE_LPM_GROUP_MAX_NUM;
	ip_mask = ip & depth_to_mask(depth);

	/* depth: 1~8 	*/
	index = (uint8_t)(ip_mask>>24);
	if(node->next == NULL){
		if(trie->current_group ==end_node){
			RTE_LOG(ERR, LPM, "LPM trie_node overflow!\n");
			goto exit;
		}
		node->next = trie->current_group;
		trie->current_group +=RTE_NODE_NUM;
		
	}


	//node->next[index].parent = node;
	node = node->next + index;
	if(depth <= 8){
		rte_trie_add_help(node, index & depth_to_mask(depth),depth,next_hop);
		return 0;
	}
	depth -=8;

	/* depth: 9~16 	*/
	index = (uint8_t)(ip_mask>>16);
	if(node->next == NULL){
		if(trie->current_group ==end_node){
			RTE_LOG(ERR, LPM, "LPM trie_node overflow!\n");
			goto exit;
		}
		node->next = trie->current_group;
		trie->current_group +=RTE_NODE_NUM;
		
	}

	//node->next[index].parent = node;
	node = node->next + index;
	if(depth <= 8){
		rte_trie_add_help(node, index& depth_to_mask(depth) ,depth,next_hop);
		return 0;
	}
	depth -=8;

	/* depth: 15~24 	*/
	index = (uint8_t)(ip_mask>>8);
	if(node->next == NULL){
		if(trie->current_group ==end_node){
			RTE_LOG(ERR, LPM, "LPM trie_node overflow!\n");
			goto exit;
		}
		node->next = trie->current_group;
		trie->current_group +=RTE_NODE_NUM;
		
	}

	//node->next[index].parent = node;
	node = node->next + index;
	if(depth <= 8){
		rte_trie_add_help(node, index& depth_to_mask(depth) ,depth,next_hop);
		return 0;
	}
	depth -=8;

	/* depth: 25~32 	*/
	index = (uint8_t)ip_mask;
	if(node->next == NULL){
		if(trie->current_group ==end_node){
			RTE_LOG(ERR, LPM, "LPM trie_node overflow!\n");
			goto exit;
		}
		node->next = trie->current_group;
		trie->current_group +=RTE_NODE_NUM;
		
	}
	//node->next[index].parent = node;
	node = node->next + index;
	if(depth <= 8){
		rte_trie_add_help(node, index& depth_to_mask(depth) ,depth,next_hop);
		return 0;
	}

 exit:
	return ENOMEM;
}

int rte_trie_free(struct rte_trie *trie){
    if(trie)
	{
		rte_free(trie->trie_node);
		trie->trie_node = NULL;
		rte_free(trie);
		trie=NULL;
	}
	return 0;
}
