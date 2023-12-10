/* ISC license. */

#include <stdint.h>
#include <string.h>

#include <skalibs/uint16.h>
#include <skalibs/uint32.h>

#include <shibari/constants.h>
#include <shibari/packet.h>

int shibari_packet_add_rr (shibari_packet *p, shibari_tdb_entry const *entry, int prefixlen, uint16_t offset, unsigned int section)
{
  uint16_t *count[4] = { &p->hdr.counts.qd, &p->hdr.counts.an, &p->hdr.counts.ns, &p->hdr.counts.nr } ;
  uint16_t rrlen = 10 + entry->data.len + (entry->flags & 1 ? 2 : 0) + (prefixlen >= 0 ? prefixlen + 2 : entry->key.len) ;
  if (p->max - p->pos < rrlen) return 0 ;
  if (entry->flags & 1)
  {
    p->buf[p->pos++] = 1 ;
    p->buf[p->pos++] = '*' ;
  }
  if (prefixlen >= 0)
  {
    memcpy(p->buf + p->pos, entry->key.s, prefixlen) ;
    p->pos += prefixlen ;
    uint16_pack_big(p->buf + p->pos, 49164 + offset) ;
    p->pos += 2 ;
  }
  else
  {
    memcpy(p->buf + p->pos, entry->key.s, entry->key.len) ;
    p->pos += entry->key.len ;
  }
  uint16_pack_big(p->buf + p->pos, entry->type) ;
  p->pos += 2 ;
  uint16_pack_big(p->buf + p->pos, SHIBARI_C_IN) ;
  p->pos += 2 ;
  uint32_pack_big(p->buf + p->pos, entry->ttl) ;
  p->pos += 4 ;
  uint16_pack_big(p->buf + p->pos, entry->data.len) ;
  p->pos += 2 ;
  memcpy(p->buf + p->pos, entry->data.s, entry->data.len) ;
  p->pos += entry->data.len ;
  (*count[section-1])++ ;
  return 1 ;
}
