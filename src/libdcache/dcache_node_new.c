/* ISC license. */

#include <stdint.h>
#include <string.h>

#include <skalibs/uint16.h>
#include <skalibs/stralloc.h>
#include <skalibs/gensetdyn.h>

#include <shibari/dcache.h>
#include "dcache-internal.h"

int dcache_node_new (dcache *z, uint32_t *idx, char const *q, uint16_t qlen, uint16_t qtype, uint16_t extra)
{
  dcache_node *node ;
  uint32_t i ;
  if (!gensetdyn_new(&z->storage, &i)) return 0 ;
  node = DNODE(z, i) ;
  if (!stralloc_ready_tuned(&node->sa, 4 + qlen + extra, 0, 0, 1)) goto err0 ;
  uint16_pack_big(node->sa.s, qtype) ;
  uint16_pack_big(node->sa.s + 2, qlen) ;
  memcpy(node->sa.s + 4, q, qlen) ;
  node->sa.len = 4 + qlen ;
  *idx = i ;
  return 1 ;

 err0:
  gensetdyn_delete(&z->storage, i) ;
  return 0 ;
}
