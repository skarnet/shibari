/* ISC license. */

#include <stdint.h>
#include <string.h>

#include <skalibs/uint16.h>
#include <skalibs/stralloc.h>
#include <skalibs/gensetdyn.h>
#include <skalibs/avltree.h>

#include <shibari/dcache.h>
#include "dcache-internal.h"

dcache_node *dcache_node_new (dcache *z, char const *key, uint16_t keylen)
{
  static tai const tai_infinite = TAI_INFINITE ;
  dcache_node *node ;
  uint32_t i ;
  if (!gensetdyn_new(&z->storage, i)) return 0 ;
  node = DNODE(z, i) ;
  if (!stralloc_ready(&node->sa, 6 + keylen)) goto err0 ;
  uint16_pack_big(node->sa.s, keylen) ;
  memcpy(node->sa.s + 2, key, keylen) ;
  node->sa.len = 2 + keylen ;
  node->entry = tai_infinite ;
  node->expire = tai_infinite ;
  return node ;

 err1:
  node->sa.len = 0 ;
 err0:
  gensetdyn_delete(&z->storage, i) ;
  return 0 ;
}
