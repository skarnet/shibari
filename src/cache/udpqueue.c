/* ISC license. */

#include <string.h>

#include <skalibs/allreadwrite.h>
#include <skalibs/tai.h>
#include <skalibs/stralloc.h>
#include <skalibs/genalloc.h>
#include <skalibs/socket.h>
#include <skalibs/ip46.h>

#include "shibari-cache-internal.h"

void udpqueue_drop (udpqueue *q)
{
  q->storage.len = 0 ;
  q->messages.len = 0 ;
  tain_add_g(&q->deadline, &tain_infinite_relative) ;
}

int udpqueue_add (udpqueue *q, uint8_t source, char const *ip, uint16_t port, char const *s, uint16_t len)
{
  size_t iplen = source ? 16 : 4 ;
  udpaux msg = { .port = port, .len = len } ;
  if (!stralloc_readyplus(&q->storage, iplen + len)) return 0 ;
  if (!genalloc_append(udpaux, &q->messages, &msg)) return 0 ;
  if (!q->storage.len) tain_add_g(&q->deadline, &g->wtto) ;
  stralloc_catb(&q->storage, ip, iplen) ;
  stralloc_catb(&q->storage, s, len) ;
  return 1 ;
}

int udpqueue_flush (udpqueue *q, uint8_t is6)
{
  size_t n = genalloc_len(udpaux, &q->messages) ;
  size_t shead = 0, head = 0 ;
  ssize_t r = 1 ;
  while (head < n)
  {
    udpaux const *msg = genalloc_s(udpaux, &q->messages) + head ;
    ssize_t r ;
#if SKALIBS_IPV6_ENABLED
    if (is6)
      r = socket_send6(q->fd, q->storage.s + shead + 16, msg->len, q->storage.s + shead, msg->port) ;
    else
#endif
      r = socket_send4(q->fd, q->storage.s + shead + 4, msg->len, q->storage.s + shead, msg->port) ;
    if (r <= 0) goto adjust ;
    shead += (is6 ? 16 : 4) + msg->len ;
  }
  udpqueue_drop(q) ;
  return 1 ;

 adjust:
  memmove(q->storage.s, q->storage.s + shead, q->storage.len - shead) ;
  q->storage.len -= shead ;
  memmove(genalloc_s(udpaux, &q->messages), genalloc_s(udpaux, &q->messages) + head, (n - head) * sizeof(udpaux)) ;
  genalloc_setlen(udpaux, &q->messages, n - head) ;
  if (shead) tain_add_g(&q->deadline, &g->wtto) ;
  return sanitize_read(r) ;
}
