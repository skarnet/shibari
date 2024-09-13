/* ISC license. */

#include <stdint.h>

#include <skalibs/uint16.h>
#include <skalibs/avltree.h>

#include <shibari/dcache.h>
#include "dcache-internal.h"

int dcache_search (dcache *z, uint32_t *idx, char const *q, uint16_t qlen, uint16_t qtype, tai const *stamp)
{
  dcache_node *node ;
  uint32_t i ;
  char key[4 + qlen] ;
  uint16_pack_big(key, qtype) ;
  uint16_pack_big(key+2, qlen) ;
  memcpy(key+4, q, qlen) ;
  if (!avltree_search(&z->by_key, &key, &i)) return -1 ;
  node = DNODE(z, i) ;
  if (node->sa.len == node->sa.a && tai_less(&node->expire, stamp))
  {
    dcache_delete(z, i) ;
    return -1 ;
  }
  *idx = i ;
  return node->sa.len == node->sa.a ;
}
