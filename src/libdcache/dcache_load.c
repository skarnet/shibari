/* ISC license. */

#include <stdint.h>
#include <string.h>
#include <errno.h>

#include <skalibs/uint16.h>
#include <skalibs/uint64.h>
#include <skalibs/buffer.h>
#include <skalibs/tai.h>
#include <skalibs/djbunix.h>
#include <skalibs/avltree.h>

#include <shibari/dcache.h>
#include "dcache-internal.h"

#include <skalibs/posixishard.h>

static inline int dcache_adjust_node (dcache *z, uint32_t i, char const *data, uint16_t datalen, tai const *entry, tai const *expire)
{
 /* can't happen. Complete if it ever can. */
  return (errno = EDOM, 0) ;
}

static inline int dcache_add_keydata (dcache *z, char const *q, uint16_t qlen, uint16_t qtype, char const *data, uint16_t datalen, tai const *entry, tai const *expire)
{
  uint32_t i ;
  if (dcache_search_g(z, &i, q, qlen, qtype)) return dcache_adjust_node(z, i, data, datalen, entry, expire) ;
  return dcache_add(z, q, qlen, qtype, data, datalen, entry, expire) ;
}

static inline int dcache_load_node (dcache *z, buffer *b)
{
  tai entry, expire ;
  uint16_t qtype, qlen, datalen ;
  char pack[TAI_PACK * 2 + 6] ;
  ssize_t r = buffer_get(b, pack, TAI_PACK * 2 + 6) ;
  if (!r) return 0 ;
  if (r < TAI_PACK * 2 + 6) return -1 ;
  tai_unpack(pack, &entry) ;
  tai_unpack(pack + TAI_PACK, &expire) ;
  uint16_unpack_big(pack + TAI_PACK * 2, &datalen) ;
  uint16_unpack_big(pack + TAI_PACK * 2 + 2, &qtype) ;
  uint16_unpack_big(pack + TAI_PACK * 2 + 4, &qlen) ;
  {
    uint32_t len = qlen + datalen ;
    char blob[len+1] ;  /* 128 kB max */
    r = buffer_get(b, blob, len + 1) ;
    if (!r) return (errno = EPIPE, -1) ;
    if (r <= len) return -1 ;
    if (blob[len]) return (errno = EPROTO, -1) ;
    if (!dcache_add_keydata(z, blob, qlen, qtype, blob + qlen, datalen, &entry, &expire)) return -1 ;
  }
  return 1 ;
}

static inline int dcache_load_from_buffer (dcache *z, buffer *b)
{
  {
    char banner[sizeof(DCACHE_MAGIC) - 1] ;
    char pack[8] ;
    if (buffer_get(b, banner, sizeof(DCACHE_MAGIC) - 1) < sizeof(DCACHE_MAGIC) - 1)
      return 0 ;
    if (memcmp(banner, DCACHE_MAGIC, sizeof(DCACHE_MAGIC) - 1)) return 0 ;
    if (buffer_get(b, pack, 8) < 8) return 0 ;
    uint64_unpack_big(pack, &z->size) ;
    if (buffer_get(b, pack, 8) < 8) return 0 ;
    uint64_unpack_big(pack, &z->motion) ;
  }
  for (;;)
  {
    int r = dcache_load_node(z, b) ;
    if (r < 0) return 0 ;
    if (!r) break ;
  }
  return 1 ;
}

#define N 8192

int dcache_load (dcache *z, char const *file)
{
  char buf[N] ;
  buffer b ;
  int fd = open_readb(file) ;
  if (fd == -1) return 0 ;
  buffer_init(&b, &buffer_read, fd, buf, N) ;
  if (!dcache_load_from_buffer(z, &b)) goto err ;
  fd_close(fd) ;
  return 1 ;

 err:
  dcache_free(z) ;
  fd_close(fd) ;
  return 0 ;
}
