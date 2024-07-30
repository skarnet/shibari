/* ISC license. */

#include <stdint.h>

#include <skalibs/avltree.h>

#include <shibari/dcache.h>
#include "dcache-internal.h"

dcache_node_t *dcache_search (dcache_t *z, char const *key, uint16_t keylen, tain const *stamp)
{
  uint32_t i ;
  dcache_key_t k = { .s = (char *)key, .len = keylen } ;
  if (avltree_search(&z->by_key, &k, &i))
  {
    if (tain_less(&DNODE(z, i)->expire, stamp))
    {
      dcache_clean_expired(z, stamp) ;
      if (!avltree_search(&z->by_key, &k, &i)) return 0 ;
    }
    return DNODE(z, i) ;
  }
  else return 0 ;
}
