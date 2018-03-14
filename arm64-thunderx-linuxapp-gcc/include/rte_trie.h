#ifndef _RTE_TRIE_H_
#define _RTE_TRIE_H_

#include <errno.h>
#include <sys/queue.h>
#include <stdint.h>
#include <stdlib.h>
#include <rte_branch_prediction.h>
#include <rte_byteorder.h>
#include <rte_memory.h>
#include <rte_common.h>
#include <rte_vect.h>
#include <rte_compat.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RTE_LPM_GROUP_MAX_NUM 256

/** Max number of characters in LPM name. */
#define RTE_LPM_NAMESIZE                32

#define RTE_NODE_NUM					256

/** Maximum depth value possible for IPv4 LPM. */
#define RTE_TRIE_MAX_DEPTH               32

struct rte_trie_node {
//	struct rte_trie_node *parent;
	struct rte_trie_node *next;
	uint8_t valid;
	uint8_t next_hop;
	uint8_t depth;
	
};



struct rte_trie{
	struct rte_trie_node *trie_node;
	char name[RTE_LPM_NAMESIZE];
	struct rte_trie_node * current_group;
};

struct rte_trie *
rte_trie_create(const char *name, int socket_id);

int
rte_trie_add(struct rte_trie *trie, uint32_t ip, uint8_t depth,
		uint32_t next_hop);

int rte_trie_node_free(struct rte_trie_node *node);
int rte_trie_free(struct rte_trie *trie);

static inline int
rte_trie_lookup(struct rte_trie *trie, uint32_t ip, uint32_t *next_hop)
{
	if(trie==NULL || next_hop == NULL)
		return -EINVAL;
	struct rte_trie_node *node = trie->trie_node;
	struct rte_trie_node *tmp0, *tmp1, *tmp2, *tmp3;
	*next_hop = 0;
	if(node->next == NULL){
		return -EINVAL;
	}
	tmp0 = node->next+((uint8_t)(ip>>24));

	if(tmp0->next){
		tmp1 = tmp0->next+((uint8_t)(ip>>16));

		if(tmp1->next){
			tmp2 = tmp1->next+((uint8_t)(ip>>8));

			if(tmp2->next){
				tmp3 = tmp2->next+((uint8_t)ip);

				if(tmp3->valid){
					*next_hop= tmp3->next_hop;
					return 0;
				}
			}
			if(tmp2->valid){

				*next_hop= tmp2->next_hop;
				return 0;
			}
		}
		if(tmp1->valid){
			*next_hop= tmp1->next_hop;
			return 0;
		}
	}
	if(tmp0->valid){

		*next_hop= tmp0->next_hop;
		return 0;
	}
	return -ENOENT;
}





#ifdef __cplusplus
}
#endif
#endif /* _RTE_TRIE_H_ */