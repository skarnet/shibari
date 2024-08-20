/* ISC license. */

#include <stdint.h>
#include <string.h>

#include <skalibs/uint16.h>
#include <skalibs/tai.h>
#include <skalibs/gensetdyn.h>
#include <skalibs/avltree.h>

#include <shibari/dcache.h>

static int key_cmp (void const *a, void const *b, void *x)
{
  int r = memcmp(a, b, 4) ;
  if (r) return r ;
  {
    char const *aa = a ;
    char const *bb = b ;
    uint16_t len ;
    uint16_unpack_big(aa+2, &len) ;
    return memcmp(aa+4, bb+4, len) ;
  }
}

static int tai_cmp (void const *a, void const *b, void *x)
{
  tai const *ta = a ;
  tai const *tb = b ;
  (void)x ;
  return tai_less(ta, tb) ? -1 : tai_less(tb, ta) ;
}

static void *key_dtok (uint32_t d, void *x)
{
  return &GENSETDYN_P(dcache_node, (gensetdyn *)x, d)->sa.s ;
}

static void *entry_dtok (uint32_t d, void *x)
{
  return &GENSETDYN_P(dcache_node, (gensetdyn *)x, d)->entry ;
}

static void *expire_dtok (uint32_t d, void *x)
{
  return &GENSETDYN_P(dcache_node, (gensetdyn *)x, d)->expire ;
}


void dcache_init (dcache *z, uint64_t max)
{
  gensetdyn_init(&z->storage, sizeof(dcache_node), max >> 9, 3, 8) ;
  avltree_init(&z->by_key, max >> 9, 3, 8, &key_dtok, &key_cmp, &z->storage) ;
  avltree_init(&z->by_entry, max >> 9, 3, 8, &entry_dtok, &tai_cmp, &z->storage) ;
  avltree_init(&z->by_expire, max >> 9, 3, 8, &expire_dtok, &tai_cmp, &z->storage) ;
  z->max = max ;
  z->size = 0 ;
  z->motion = 0 ;
}
