/* ISC license. */

#include <s6-dns/s6dns-message.h>

#include <shibari/packet.h>

void shibari_packet_init (shibari_packet *p, char *buf, uint32_t max, int istcp)
{
  p->hdr = s6dns_message_header_zero ;
  p->buf = istcp ? buf + 2 : buf ;
  p->max = istcp ? max - 2 : max ;
  p->pos = 0 ;
  p->flagtcp = !!istcp ;
}
