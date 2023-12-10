/* ISC license. */

#include <string.h>

#include <skalibs/uint16.h>

#include <shibari/constants.h>
#include <shibari/packet.h>

void shibari_packet_begin (shibari_packet *p, uint16_t id, s6dns_domain_t const *q, uint16_t qtype)
{
  p->hdr.id = id ;
  p->hdr.qr = 1 ;
  p->hdr.opcode = 0 ;
  p->hdr.aa = 0 ;
  p->hdr.tc = 0 ;
  p->hdr.rd = 0 ;
  p->hdr.ra = 0 ;
  p->hdr.z = 0 ;
  p->hdr.rcode = 0 ;
  p->hdr.counts.qd = 1 ;
  p->hdr.counts.an = 0 ;
  p->hdr.counts.ns = 0 ;
  p->hdr.counts.nr = 0 ;
  p->pos = 12 ;
  memcpy(p->buf + p->pos, q->s, q->len) ;
  p->pos += q->len ;
  uint16_pack_big(p->buf + p->pos, qtype) ;
  p->pos += 2 ;
  uint16_pack_big(p->buf + p->pos, SHIBARI_C_IN) ;
  p->pos += 2 ;
}
