/* ISC license. */

#include <stdint.h>

#include <skalibs/tai.h>
#include <skalibs/avltree.h>

#include <shibari/dcache.h>
#include "dcache-internal.h"

void dcache_clean_expired (dcache *z, tai const *stamp)
{
  for (;;)
  {
    uint32_t i ;
    if (!avltree_min(&z->by_expire, &i)) break ;
    if (!tai_less(&DNODE(z, i)->expire, stamp)) break ;
    dcache_delete(z, i) ;
  }
}
