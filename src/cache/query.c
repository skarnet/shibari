/* ISC license. */

#include <stdint.h>

#include <s6-dns/s6dns-engine.h>

#include "shibari-cache-internal.h"

static uint16_t query_delete (query *q)
{
  uint16_t newi = q->prev ;
  QUERY(newi)->next = q->next ;
  QUERY(q->next)->prev = q->prev ;
  q->xindex = UINT16_MAX ;
  return newi ;
}

uint16_t query_abort (uint16_t id)
{
  query *q = QUERY(id) ;
  s6dns_engine_recycle(&q->dt) ;
  return query_delete(q) ;
}

uint16_t query_fail (uint16_t id)
{
  query *q = QUERY(id) ;

  if (q->source == 2) tcpconnection_removequery(TCPCONNECTION(q->i), id) ;
  return query_delete(q) ;
}

uint16_t query_succeed (uint16_t id)
{
  query *q = QUERY(id) ;

  if (q->source == 2) tcpconnection_removequery(TCPCONNECTION(q->i), id) ;
  return query_delete(q) ;
}

int query_new (uint8_t source, uint16_t i, char const *ip, uint16_t port, char const *s, uint16_t len)
{
  return 1 ;
}
