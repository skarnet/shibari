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

int udpqueue_add4 (udpqueue *q, char const *ip, uint16_t port, char const *s, uint16_t len)
{
  udp4msg msg = { .port = port, .len = len } ;
  if (!stralloc_readyplus(&q->storage, len)) return 0 ;
  memcpy(msg.ip, ip, 4) ;
  if (!genalloc_append(udp4msg, &q->messages, &msg)) return 0 ;
  if (!q->storage.len) tain_add_g(&q->deadline, &g->wtto) ;
  stralloc_catb(&q->storage, s, len) ;
  return 1 ;
}

int udpqueue_flush4 (udpqueue *q)
{
  size_t n = genalloc_len(udp4msg, &q->messages) ;
  size_t shead = 0, head = 0 ;
  ssize_t r = 1 ;
  while (head < n)
  {
    udp4msg const *msg = genalloc_s(udp4msg, &q->messages) + head ;
    ssize_t r = socket_send4(q->fd, q->storage.s + shead, msg->len, msg->ip, msg->port) ;
    if (r <= 0) goto adjust ;
    shead += msg->len ;
  }
  udpqueue_drop(q) ;
  return 1 ;

 adjust:
  memmove(q->storage.s, q->storage.s + shead, q->storage.len - shead) ;
  q->storage.len -= shead ;
  memmove(genalloc_s(udp4msg, &q->messages), genalloc_s(udp4msg, &q->messages) + head, (n - head) * sizeof(udp4msg)) ;
  genalloc_setlen(udp4msg, &q->messages, n - head) ;
  if (shead) tain_add_g(&q->deadline, &g->wtto) ;
  return sanitize_read(r) ;
}

#ifdef SKALIBS_IPv6_ENABLED

int udpqueue_add6 (udpqueue *q, char const *ip, uint16_t port, char const *s, uint16_t len)
{
  udp6msg msg = { .port = port, .len = len } ;
  if (!stralloc_readyplus(&q->storage, len)) return 0 ;
  memcpy(msg.ip, ip, 16) ;
  if (!genalloc_append(udp6msg, &q->messages, &msg)) return 0 ;
  if (!q->storage.len) tain_add_g(&q->deadline, &g->wtto) ;
  stralloc_catb(&q->storage, s, len) ;
  return 1 ;
}

int udpqueue_flush6 (udpqueue *q)
{
  size_t n = genalloc_len(udp6msg, &q->messages) ;
  size_t shead = 0, head = 0 ;
  ssize_t r = 1 ;
  while (head < n)
  {
    udp6msg const *msg = genalloc_s(udp4msg, &q->messages) + head ;
    r = socket_send6(q->fd, q->storage.s + shead, msg->len, msg->ip, msg->port) ;
    if (r <= 0) goto adjust ;
    shead += msg->len ;
  }
  udpqueue_drop(q) ;
  return 1 ;

 adjust:
  memmove(q->storage.s, q->storage.s + shead, q->storage.len - shead) ;
  q->storage.len -= shead ;
  memmove(genalloc_s(udp6msg, &q->messages), genalloc_s(udp6msg, &q->messages) + head, (n - head) * sizeof(udp6msg)) ;
  genalloc_setlen(udp6msg, &q->messages, n - head) ;
  if (shead) tain_add_g(&q->deadline, &g->wtto) ;
  return sanitize_read(r) ;
}

#endif
