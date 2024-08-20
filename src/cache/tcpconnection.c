/* ISC license. */

#include <stdint.h>
#include <errno.h>

#include <skalibs/uint16.h>
#include <skalibs/allreadwrite.h>
#include <skalibs/error.h>
#include <skalibs/tai.h>
#include <skalibs/djbunix.h>
#include <skalibs/bufalloc.h>
#include <skalibs/genalloc.h>

#include "shibari-cache-internal.h"

void tcpconnection_removetask (tcpconnection *p, uint16_t id)
{
  uint16_t *tab = genalloc_s(uint16_t, &p->tasks) ;
  uint16_t n = genalloc_len(uint16_t, &p->tasks) ;
  uint16_t i = 0 ;
  for (; i < n ; i++) if (id == tab[i]) break ;
  if (i >= n) return ;
  tab[i] = tab[--n] ;
  genalloc_setlen(uint16_t, &p->tasks, n) ;
}

uint16_t tcpconnection_delete (tcpconnection *p)
{
  uint16_t newi = p->prev ;
  p->out.x.len = 0 ;
  p->in.len = 0 ;
  p->instate = 0 ;
  fd_close(p->out.fd) ;
  for (uint16_t i = 0 ; i < genalloc_len(uint16_t, &p->tasks) ; i++)
    dnstask_abort(genalloc_s(uint16_t, &p->tasks)[i]) ;
  genalloc_setlen(uint16_t, &p->tasks, 0) ;
  TCPCONNECTION(newi)->next = p->next ;
  TCPCONNECTION(p->next)->prev = p->prev ;
  p->xindex = UINT16_MAX ;
  return newi ;
}

int tcpconnection_add (tcpconnection *p, char const *s, uint16_t len)
{
  char pack[2] ;
  if (!stralloc_readyplus(&p->out.x, 2 + len)) return 0 ;
  uint16_pack_big(pack, len) ;
  bufalloc_put(&p->out, pack, 2) ;
  bufalloc_put(&p->out, s, len) ;
  return 0 ;
}

int tcpconnection_flush (tcpconnection *p)
{
  return bufalloc_flush(&p->out) ? 1 :
    error_isagain(errno) ? 0 : -1 ;
}

static void tcpconnection_init (tcpconnection *p, int fd)
{
  if (!p->out.op) bufalloc_init(&p->out, &fd_write, fd) ;
  else { p->out.fd = fd ; p->out.x.len = 0 ; }
  tain_add_g(&p->rdeadline, &tain_infinite_relative) ;
  tain_add_g(&p->wdeadline, &tain_infinite_relative) ;
}

void tcpconnection_new (int fd)
{
  uint16_t n = genset_new(&g->tcpconnections) ;
  tcpconnection *sentinel = TCPCONNECTION(g->tcpsentinel) ;
  tcpconnection *p = TCPCONNECTION(n) ;
  tcpconnection_init(p, fd) ;
  p->prev = g->tcpsentinel ;
  p->next = sentinel->next ;
  TCPCONNECTION(sentinel->next)->prev = n ;
  sentinel->next = n ;
}
