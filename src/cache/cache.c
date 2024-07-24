/* ISC license. */

#include <skalibs/uint64.h>
#include <skalibs/posixplz.h>
#include <skalibs/strerr.h>

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
      unlink_void(file) ;
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
