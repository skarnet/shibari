/* ISC license. */

#include <skalibs/avltree.h>

#include "dcache-internal.h"

int dcache_node_add (dcache *z, uint32_t i)
{
  dcache_node *node = DNODE(z, i) ;
  if (!avltree_insert(&z->by_key, i)) return 0 ;
  if (node->sa.len < node->sa.a) return 1 ;
  if (!avltree_insert(&z->by_entry, i)) goto err0 ;
  if (!avltree_insert(&z->by_expire, i)) goto err1 ;
  return 1 ;

 err1:
  avltree_delete(&z->by_entry, &node->entry) ;
 err0:
  avltree_delete(&z->by_key, node->sa.s) ;
  return 0 ;
}
