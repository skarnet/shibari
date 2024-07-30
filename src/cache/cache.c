/* ISC license. */

#include <string.h>

#include <skalibs/uint16.h>
#include <skalibs/posixplz.h>
#include <skalibs/strerr.h>

#include <s6-dns/s6dns-domain.h>

#include <shibari/dcache.h>
#include "shibari-cache-internal.h"

static dcache_t cache = DCACHE_ZERO ;

void cache_init (uint64_t cachesize)
{
  dcache_init(&cache, cachesize) ;
}

void cache_dump (void)
{
  if (g->dumpfile)
  {
    if (!dcache_save(&cache, g->dumpfile))
    {
      strerr_warnwu2sys("save cache contents to ", g->dumpfile) ;
      unlink_void(g->dumpfile) ;
    }
  }
}

void cache_load (void)
{
  if (g->dumpfile)
  {
    if (!dcache_load(&cache, g->dumpfile))
      strerr_warnwu2sys("load cache contents from ", g->dumpfile) ;
  }
}

int cache_search (s6dns_domain_t const *name, uint16_t qtype, dcache_key_t *data)
{
  dcache_node_t *node ;
  char key[name->len + 1] ;
  uint16_pack_big(key, qtype) ;
  memcpy(key + 2, name->s, name->len - 1) ;
  node = dcache_search_g(&cache, key, name->len + 1) ;
  if (!node) return 0 ;
  data->s = node->key.s + node->key.len ;
  data->len = node->datalen ;
  return 1 ;
}
