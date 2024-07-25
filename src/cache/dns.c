/* ISC license. */

#include <skalibs/uint16.h>

#include <s6-dns/s6dns.h>

#include "shibari-cache-internal.h"

int dns_newquery (uint8_t source, uint16_t i, char const *ip, uint16_t port, char const *buf, uint16_t len)
{
  dcache_key_t data ;
  s6dns_message_header_t hdr ;
  s6dns_message_counts_t counts ;
  s6dns_domain_t name ;
  unsigned int pos ;
  unsigned int rcode ;
  uint16_t qtype ;
  char key[257] ;

  if (!s6dns_message_parse_init(&hdr, &counts, buf, len, &pos)) return 1 ;
  if (hdr.opcode) { rcode = 4 ; goto err ; }
  if (!hdr.rd) { rcode = 1 ; goto err ; }
  if (!s6dns_message_parse_question(&counts, &name, &qtype, buf, len, &pos)
   || !s6dns_domain_encode(&name))
  {
    rcode = errno == ENOTSUP ? 4 : 1 ;
    goto answer ;
  }
  
  if (cache_search(&name, qtype, &data)) goto got ;
  return 1 ;

 answer:
  return 1 ;
 err:
 got :
  return 1 ;
}
