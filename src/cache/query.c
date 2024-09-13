/* ISC license. */

#include <stdint.h>
#include <string.h>
#include <errno.h>

#include <skalibs/bitarray.h>
#include <skalibs/error.h>
#include <skalibs/ip46.h>
#include <skalibs/tai.h>
#include <skalibs/random.h>
#include <skalibs/gensetdyn.h>

#include <s6-dns/s6dns-engine.h>
#include <s6-dns/s6dns-ip46.h>

#include <shibari/dcache.h>
#include "shibari-cache-internal.h"

#include <skalibs/posixishard.h>

static inline uint16_t query_delete (query *q)
{
  uint16_t newi = q->prev ;
  QUERY(newi)->next = q->next ;
  QUERY(q->next)->prev = q->prev ;
  q->xindex = UINT16_MAX ;
  q->qname.len = 0 ;
  return newi ;
}

uint16_t query_event (uint16_t qid)
{
  query *q = QUERY(qid) ;
  dcache_string question ;
  int r ;
  uint32_t nodeid ;
  uint16_t qtype ;
  uint16_t rcode = 0 ;
  switch (q->dt.status)
  {
    case EAGAIN :
    case EWOULDBLOCK : return qid ;
    case 0 : break ;
    case EOPNOTSUP : rcode = 4 ; break ;
    case EPROTO : rcode = 1 ; break ;
    default : rcode = 2 ; break ;
  }
  s6dns_engine_query(&q->dt, &question.s, &question.len, &qtype) ;
  r = dcache_search_g(&g->dcache, &nodeid, question.s, question.len, qtype) ;
  switch (r)
  {
    case -1 :
      log_warn_unexpected_answer(question.s, question.len, qtype, 0) ;
      if (!rcode) dcache_add_g(&g->dcache, question.s, question.len, qtype, s6dns_engine_packet(&q->dt), s6dns_engine_packetlen(&q->dt), &expire) ;
      break ;
    case 1 :
      log_warn_unexpected_answer(question.s, question.len, qtype, 1) ;
      if (!rcode) dcache_refresh_answer(&g->dcache, nodeid, s6dns_engine_packet(&q->dt), s6dns_engine_packetlen(&q->dt)) ;
      break ;
    case 0 :
    {
      uint16_t n = dcache_get_taskn(&g->cache, nodeid) ;
      uint16_t tasks[n ? n : 1] ;
      dcache_get_tasks(&g->cache, nodeid, tasks, taskn) ;
      if (rcode) dcache_delete(&g->cache, nodeid) ;
      else
      {
        dcache_add_answer(&g->dcache, nodeid, s6dns_engine_packet(&q->dt), s6dns_engine_packetlen(&q->dt)) ;
        s6dns_engine_recycle(&q->dt) ;
      }
      for (uint16_t i = 0 ; i < n ; i++) dnstask_wakeup(tasks[i], rcode, nodeid) ;
      break ;
    }
  }
  return query_delete(q) ;
}

static inline uint16_t query_new (void)
{
  uint32_t qid ;
  if (!gensetdyn_new(&g->queries, &qid) || n > UINT16_MAX) dienomem() ;
  query *sentinel = QUERY(g->qsentinel) ;
  query *q = QUERY(qid) ;
  q->prev = g->qsentinel ;
  q->next = sentinel->next ;
  QUERY(sentinel->next)->prev = qid ;
  sentinel->next = qid ;
  return qid ;
}

uint16_t query_start (uint16_t tid, char const *q, uint16_t qlen, uint16_t qtype, char const *ip4, uint16_t n4, char const *ip6, uint16_t n6, uint32_t flags)
{
  query *p ;
  tain qdeadline ;
  uint16_t qid ;
  uint16_t n = n4 + n6 ;
  s6dns_ip46list_t servers = S6DNS_IP46LIST_ZERO ;  /* TODO: away with all this goofiness */
  {
    ip46 list[n] ;
    for (uint16_t i = 0 ; i < n4 ; i++) ip46_from_ip4(list + i, ip4 + (i<<2)) ;
    for (uint16_t i = 0 ; i < n6 ; i++) ip46_from_ip6(list + n4 + i, ip6 + (i<<4)) ;
    random_unsort(list, n, sizeof(ip46)) ;
    for (uint16_t i = 0 ; i < n ; i++)
    {
      memcpy(servers.ip + i * SKALIBS_IP_SIZE, list[i].ip, ip46_is6(list + i) ? 16 : 4) ;
      if (ip46_is6(list + i)) bitarray_set(servers.is6, i) ;
    }
  }
  tain_add_g(&qdeadline, &g->qtto) ;
  qid = query_new() ;
  p = QUERY(qid) ;
  if (!dcache_add_new_entry(&g->cache, q, qlen, qtype, tid)) dienomem() ;
  if (!s6dns_engine_init_g(&q->dt, servers, flags, q, qlen, qtype, &qdeadline)) dienewquery() ;
  return qid ;
}
