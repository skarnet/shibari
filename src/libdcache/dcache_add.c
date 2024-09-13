/* ISC license. */

#include <stdint.h>
#include <string.h>

#include <shibari/dcache.h>
#include "dcache-internal.h"

#include <skalibs/posixishard.h>

int dcache_add (dcache *z, char const *q, uint16_t qlen, uint16_t qtype, char const *data, uint16_t datalen, tai const *entry, tai const *expire)
{
  uint32_t i ;
  dcache_node *node ;
  if (!dcache_node_new(z, &i, q, qlen, qtype, datalen)) return 0 ;
  node = DNODE(z, i) ;
  node->entry = *entry ;
  node->expire = *expire ;
  memcpy(node->sa.s + node->sa.len, data, datalen) ;
  node->sa.len += datalen ;
  if (!dcache_node_add(z, i))
  {
    dcache_node_free(node) ;
    return 0 ;
  }
  return 1 ;
}
