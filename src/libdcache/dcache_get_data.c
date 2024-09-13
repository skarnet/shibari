/* ISC license. */

#include <stdint.h>

#include <skalibs/uint16.h>

#include <shibari/dcache.h>
#include "dcache-internal.h"

void dcache_get_data (dcache *z, uint32_t nid, dcache_string *data)
{
  dcache_node *node = DNODE(z, nid) ;
  uint16_t qlen ;
  uint16_unpack_big(node->sa.s + 2, &qlen) ;
  data->s = node->sa.s + 4 + qlen ;
  data->len = node->sa.len - qlen - 4 ;
}
