/* ISC license. */

#include <stdint.h>

#include <skalibs/uint16.h>
#include <skalibs/uint32.h>


#include <s6-dns/s6dns.h>

#include "shibari-cache-internal.h"

int dns_ask (dcache_string *answer, uint8_t source, uint16_t sid, char const *q, uint16_t qlen, uint16_t qtype)
{
  uint32_t i ;
  int r = dcache_searchnode_g(&g->cache, &i, q, qlen, qtype) ;
  if (r > 0)
  {
    dcache_string data ;
    dcache_node_get_data(&g->cache, i, answer) ;
    return 1 ;
  }
  else if (!r)
  {
    dns_task_new()
  }
}

uint16_t dnstask_new  (uint8_t source, uint16_t sid, char const *ip, uint16_t port, uint16_t qid, char const *q, uint16_t qlen, uint16_t qtype)
{
  uint16_t i = genset_new(&g->dnstasks) ;
  dnstask *task = DNSTASK(i) ;
  if (!stralloc_ready(&task->sa, 6 + qlen)) dienomem() ;
  task->source = source ;
  task->sid = sid ;
  if (source < 2)
  {
    memcpy(task->ip, ip, source ? 16 : 4) ;
    task->port = port ;
  }
  else
  {
    memset(task->ip, 0, SKALIBS_IP_SIZE) ;
    task->port = 0 ;
  }
  task->spin = 0 ;
  task->prefixlen = 0 ;
  uint16_pack_big(task->sa.s, qtype) ;
  memcpy(task->sa.s + 2, q, qlen) ;
  uint32_pack_big(task->sa.s + 2 + qlen, 6 + qlen) ;
  task->sa.len = 6 + qlen ;
  return i ;
}

int dns_start_query (uint8_t source, uint16_t sid, char const *ip, uint16_t port, uint16_t qid, char const *q, uint16_t qlen, uint16_t qtype)
{
  uint16_t tid = dnstask_new(source, sid, ip, port, qid, q, qlen, qtype) ;
  dnstask *task = DNSTASK(i) ;
  
}


int dns_start (uint8_t source, uint16_t i, char const *ip, uint16_t port, char const *buf, uint16_t len)
{
  s6dns_message_header_t hdr ;
  s6dns_message_counts_t counts ;
  s6dns_domain_t name ;
  unsigned int pos ;
  unsigned int rcode ;
  int r;
  uint16_t qtype ;

  if (!s6dns_message_parse_init(&hdr, &counts, buf, len, &pos)
   || !s6dns_message_parse_question(&counts, &name, &qtype, buf, len, &pos)
   || !s6dns_domain_encode(&name)
   || counts.qd || counts.an || counts.ns || counts.nr)
    return 0 ;
  if (hdr.opcode) return dns_error(source, i, ip, port, &name, qtype, hdr.id, 4) ;
  if (!hdr.rd) return dns_error(source, i, ip, port, &name, qtype, hdr.id, 9) ;

  r = dns_ask(&data, source, i, name.s, name.len, qtype) ;
  return r > 0 ?
      dns_need_glue(name.s, name.len, qtype, data.s, data.len) ?
        dns_start_glue(source, i, ip, port, hdr.id, name.s, name.len, qtype, data.s, data.len) :
        dns_answer(source, i, ip, port, hdr.id, name.s, name.len, qtype, data.s, data.len) :
    r < 0 ?
      dns_start_query(source, i, ip, port, hdr.id, name.s, name.len, qtype) :
      dns_start_wait(source, i, ip, port, hdr.id, name.s, name.len, qtype, (dcache_node *)data.s) ;
}
