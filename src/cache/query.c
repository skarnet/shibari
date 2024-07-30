/* ISC license. */

#include <stdint.h>

#include <s6-dns/s6dns.h>

#include <shibari/constants.h>
#include "shibari-cache-internal.h"

static uint16_t query_delete (query *q)
{
  uint16_t newi = q->prev ;
  QUERY(newi)->next = q->next ;
  QUERY(q->next)->prev = q->prev ;
  q->xindex = UINT16_MAX ;
  q->qname.len = 0 ;
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

int query_end (uint8_t source, uint16_t i, char const *ip, uint16_t port, char const *buf, uint16_t len)
{
  return source < 2 ?
    udpqueue_add(g->udpqueues[source] + i, source, ip, port, buf, len) :
    tcpconnection_add(g->tcpconnections + i, buf, len) ;
}

int query_error (uint8_t source, uint16_t i, char const *ip, uint16_t port, s6dns_domain_t *name, uint16_t qtype, uint16_t id, unsigned int rcode)
{
  s6dns_message_header_t hdr = S6DNS_MESSAGE_HEADER_ZERO ;
  unsigned int pos = 12 ;
  char pkt[name->len + 16] ;
  hdr.id = id ;
  hdr.qr = 1 ;
  hdr.ra = 1 ;
  hdr.rcode = rcode ;
  hdr.counts.qd = 1 ;
  s6dns_message_header_pack(pkt, &hdr) ;
  memcpy(pkt + pos, name->s, name->len) ; pos += name->len ;
  uint16_pack_big(pkt + pos, qtype) ; pos += 2 ;
  uint16_pack_big(pkt + pos, SHIBARI_C_IN) ; pos += 2 ;
  return query_end(source, i, ip, port, pkt, pos) ;
}

static void query_init (query *q, uint8_t source, uint16_t i, char const *ip, uint16_t port, s6dns_domain_t const *name, uint16_t qtype)
{
  q->source = source ;
  q->i = i ;
  if (source < 2)
  {
    memcpy(q->ip, ip, source ? 16 : 4) ;
    q->port = port ;
  }
  q->port = port ;
  if (!stralloc_catb(&q->qname, name->s, name->len)) dienomem() ;
  q->qtype = qtype ;
  q->prefixlen = 0 ;
}

static query *query_new (uint8_t source, uint16_t i, char const *ip, uint16_t port, s6dns_domain_t const *name, uint16_t qtype)
{
  uint16_t n = genset_new(&g->queries) ;
  query *sentinel = QUERY(g->qsentinel) ;
  query *q = QUERY(n) ;
  query_init(q, source, i, ip, port, name, type) ;
  q->prev = g->qsentinel ;
  q->next = sentinel->next ;
  QUERY(sentinel->next)->prev = n ;
  sentinel->next = n ;
  return q ;
}

int query_start (uint8_t source, uint16_t i, char const *ip, uint16_t port, char const *buf, uint16_t len)
{
  dcache_key_t data ;
  s6dns_message_header_t hdr ;
  s6dns_message_counts_t counts ;
  s6dns_domain_t name ;
  unsigned int pos ;
  unsigned int rcode ;
  uint16_t qtype ;

  if (!s6dns_message_parse_init(&hdr, &counts, buf, len, &pos)
   || !s6dns_message_parse_question(&counts, &name, &qtype, buf, len, &pos)
   || !s6dns_domain_encode(&name)) return 0 ;
  if (hdr.opcode) return query_error(source, i, ip, port, &name, qtype, hdr.id, 4) ;
  if (!hdr.rd) return query_error(source, i, ip, port, &name, qtype, hdr.id, 9) ;

  if (cache_search(&name, qtype, &data))
    return query_end(source, i, ip, port, data.s, data.len) ;

  {
    uint16_t j = genset_new(&g->queries) ;
    query *q = QUERY(j) ;
  }

  return 1 ;
}

