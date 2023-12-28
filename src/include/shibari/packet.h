/* ISC license. */

#ifndef SHIBARI_PACKET_H
#define SHIBARI_PACKET_H

#include <stdint.h>

#include <skalibs/buffer.h>
#include <skalibs/cdb.h>
#include <skalibs/tai.h>

#include <s6-dns/s6dns-domain.h>
#include <s6-dns/s6dns-message.h>

#include <shibari/tdb.h>

typedef struct shibari_packet_s shibari_packet, *shibari_packet_ref ;
struct shibari_packet_s
{
  s6dns_message_header_t hdr ;
  char *buf ;
  uint16_t max ;
  uint16_t pos ;
  uint8_t flagtcp : 1 ;
} ;
#define SHIBARI_PACKET_ZERO { .hdr = S6DNS_MESSAGE_HEADER_ZERO, .buf = "", .pos = 0, .flagtcp = 0 }
#define SHIBARI_PACKET_INIT(rbuf, rmax, tcp) { .hdr = S6DNS_MESSAGE_HEADER_ZERO, .buf = tcp ? rbuf + 2 : rbuf, .max = tcp ? rmax - 2 : rmax, .pos = 0, .flagtcp = !!tcp }

extern void shibari_packet_init (shibari_packet *, char *, uint32_t, int) ;

extern void shibari_packet_begin (shibari_packet *, uint16_t, s6dns_domain_t const *, uint16_t) ;
extern void shibari_packet_end (shibari_packet *) ;

extern int shibari_packet_add_rr (shibari_packet *, shibari_tdb_entry const *, int, uint16_t, unsigned int) ;
extern unsigned int shibari_packet_add_glue (shibari_packet *, cdb const *, char const *, uint16_t, uint16_t, char const *, uint16_t, uint16_t, uint16_t, char const *, tain const *) ;
extern unsigned int shibari_packet_assert_authority (shibari_packet *, cdb const *, char const *, uint16_t, uint16_t, char const *, tain const *) ;

extern unsigned int shibari_packet_tdb_answer_query (shibari_packet *, cdb const *, s6dns_message_header_t const *, s6dns_domain_t const *, uint16_t, char const *, tain const *) ;
extern int shibari_packet_tdb_axfr (buffer *, char const *, char const *, cdb const *, s6dns_message_header_t const *, s6dns_domain_t const *, shibari_packet *, tain const *, tain const *, tain *) ;
#define shibari_packet_tdb_axfr_g(b, axfrok, loc, tdb, qhdr, zone, pkt, deadline, wstamp) shibari_packet_tdb_axfr(b, axfrok, loc, tdb, qhdr, zone, pkt, deadline, (wstamp), &STAMP)

#endif
