/* ISC license. */

#include <stdint.h>
#include <string.h>
#include <errno.h>

#include <skalibs/uint64.h>
#include <skalibs/alloc.h>
#include <skalibs/tai.h>
#include <skalibs/gensetdyn.h>
#include <skalibs/avlnode.h>
#include <skalibs/avltree.h>

#include <shibari/dcache.h>
#include "dcache-internal.h"

#include <skalibs/posixishard.h>

static inline void dcache_gc_by_entry (dcache *z, uint64_t max)
{
  while (z->size > max)
  {
    uint32_t oldest ;
    if (!avltree_min(&z->by_entry, &oldest)) break ;
    dcache_delete(z, oldest) ;
  }
}

static inline int dcache_add_data_to_node (dcache *z, uint32_t i, uint16_t qlen, char const *data, uint16_t datalen, tai const *expire, tai const *stamp)
{
  dcache_node *node = DNODE(z, i) ;
  size_t len = 4 + qlen + datalen ;
  if (node->sa.len == node->sa.a) return (errno = EDOM, 0) ;
  if (!stralloc_ready_tuned(&node->sa, len, 0, 0, 1)) return 0 ;
  node->entry = *stamp ;
  node->expire = *expire ;
  if (!avltree_insert(&z->by_entry, i)) return 0 ;
  if (!avltree_insert(&z->by_expire, i))
  {
    avltree_delete(&z->by_entry, &node->entry) ;
    return 0 ;
  }
  memcpy(node->sa.s + 4 + qlen, data, datalen) ;
  node->sa.len = len ;
  if (!stralloc_shrink(&node->sa)) node->sa.a = len ;
  z->size += DCACHE_NODE_OVERHEAD + len ;
  z->motion += DCACHE_NODE_OVERHEAD + len ;
  return 1 ;
}

int dcache_add_data (dcache *z, char const *q, uint16_t qlen, uint16_t qtype, char const *data, uint16_t datalen, tai const *expire, tai const *stamp)
{
  uint64_t size = DCACHE_NODE_OVERHEAD + qlen + datalen + 4 ;
  uint32_t i ;
  if (size > z->max) return (errno = EINVAL, 0) ;
  if (z->size > z->max - size) dcache_clean_expired(z, stamp) ;
  if (z->size > z->max - size) dcache_gc_by_entry(z, z->max - size) ;
  if (z->size > z->max - size) return (errno = ENOBUFS, 0) ;
  if (!dcache_searchnode(z, &i, q, qlen, qtype, stamp)) return 0 ;
  if (!dcache_add_data_to_node(z, i, qlen, data, datalen, expire, stamp)) return 0 ;
  z->size += size ;
  z->motion += size ;
  return 1 ;
}
