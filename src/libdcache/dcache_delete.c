/* ISC license. */

#include <skalibs/stralloc.h>
#include <skalibs/gensetdyn.h>
#include <skalibs/avltree.h>

#include <shibari/dcache.h>
#include "dcache-internal.h"

void dcache_delete (dcache *z, uint32_t i)
{
  dcache_node *node = DNODE(z, i) ;
  if (node->sa.len == node->sa.a)
  {
    avltree_delete(&z->by_expire, &node->expire) ;
    avltree_delete(&z->by_entry, &node->entry) ;
  }
  avltree_delete(&z->by_key, &node->sa.s) ;
  z->size -= DCACHE_NODE_OVERHEAD + node->sa.len ;
  node->sa.len = 0 ;
  gensetdyn_delete(&z->storage, i) ;
}
