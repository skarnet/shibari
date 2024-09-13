/* ISC license. */

#ifndef SHIBARI_DCACHE_H
#define SHIBARI_DCACHE_H

#include <stdint.h>

#include <skalibs/uint64.h>
#include <skalibs/tai.h>
#include <skalibs/gensetdyn.h>
#include <skalibs/avltree.h>

#define DCACHE_MAGIC "--DCACHE--\n"

typedef struct dcache_string_s dcache_string, *dcache_string_ref ;
struct dcache_string_s
{
  char *s ;
  uint16_t len ;
} ;

typedef struct dcache_node_s dcache_node, *dcache_node_ref ;
struct dcache_node_s
{
  stralloc sa ;
  tai entry ;
  tai expire ;
} ;
#define DCACHE_NODE_ZERO = { .sa = STRALLOC_ZERO, .entry = TAI_INFINITE, .expire = TAI_INFINITE }

typedef struct dcache_s dcache, *dcache_ref ;
struct dcache_s
{
  gensetdyn storage ; /* dcache_node */
  avltree by_key ;
  avltree by_entry ;
  avltree by_expire ;
  uint64_t max ;
  uint64_t size ;
  uint64_t motion ;
} ;
#define DCACHE_ZERO { .storage = GENSETDYN_ZERO, .by_key = AVLTREE_ZERO, .by_entry = AVLTREE_ZERO, .by_expire = AVLTREE_ZERO, .max = 0, .size = 0, .motion = 0 }

extern void dcache_init (dcache *, uint64_t) ;

extern int dcache_search (dcache *, uint32_t *, char const *, uint16_t, uint16_t, tai const *) ;
#define dcache_search_g(d, idx, q, qlen, qtype) dcache_search(d, idx, q, qlen, (qtype), tain_secp(&STAMP))

extern void dcache_clean_expired (dcache *, tai const *) ;
#define dcache_clean_expired_g(d) dcache_clean_expired((d), tain_secp(&STAMP))

extern void dcache_free (dcache *) ;


extern int dcache_add (dcache *, char const *, uint16_t, uint16_t, char const *, uint16_t, tai const *, tai const *) ;
#define dcache_add_g(z, q, qlen, qtype, data, datalen, expire) dcache_add(z, q, qlen, qtype, data, datalen, tain_secp(&STAMP), expire)

extern int dcache_save (dcache const *, char const *) ;
extern int dcache_load (dcache *, char const *) ;

#endif
