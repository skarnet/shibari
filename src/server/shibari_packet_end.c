/* ISC license. */

#include <skalibs/uint16.h>

#include <s6-dns/s6dns-message.h>

#include <shibari/packet.h>

void shibari_packet_end (shibari_packet *p)
{
  s6dns_message_header_pack(p->buf, &p->hdr) ;
  if (p->flagtcp) uint16_pack_big(p->buf - 2, p->pos) ;
}
