/* ISC license. */

#include <stdint.h>
#include <string.h>

#include <skalibs/bytestr.h>
#include <skalibs/cdb.h>
#include <skalibs/tai.h>
#include <skalibs/unix-timed.h>

#include <s6-dns/s6dns-domain.h>
#include <s6-dns/s6dns-message.h>

#include <shibari/constants.h>
#include <shibari/tdb.h>
#include <shibari/packet.h>
#include <shibari/util.h>

static int add (buffer *b, shibari_packet *pkt, shibari_tdb_entry const *entry, int prefixlen, uint16_t id, s6dns_domain_t const *zone, tain const *deadline, tain *stamp)
{
  if (!shibari_packet_add_rr(pkt, entry, prefixlen, 0, 2))
  {
    shibari_packet_end(pkt) ;
    if (!buffer_timed_put(b, pkt->buf - 2, pkt->pos + 2, deadline, stamp)) return 0 ;
    shibari_packet_begin(pkt, id, zone, SHIBARI_T_AXFR) ;
    shibari_packet_add_rr(pkt, entry, prefixlen, 0, 2) ;
  }
  return 1 ;
}

#define SEPS "/,; \t\n"

int shibari_packet_tdb_axfr (buffer *b, char const *axfrok, char const *loc, cdb const *tdb, s6dns_message_header_t const *qhdr, s6dns_domain_t const *zone, shibari_packet *pkt, tain const *deadline, tain const *wstamp, tain *stamp)
{
  shibari_tdb_entry soa ;
  shibari_tdb_entry cur ;
  s6dns_domain_t z = *zone ;
  uint32_t pos = CDB_TRAVERSE_INIT() ;
  if (axfrok && axfrok[0] != '*')
  {
    unsigned int zonelen ;
    size_t len = strlen(axfrok) + 1 ;
    char zbuf[256] ;
    if (!s6dns_domain_decode(&z)) return 1 ;
    zonelen = s6dns_domain_tostring(zbuf, 256, &z) ;
    while (len)
    {
      size_t seppos = byte_in(axfrok, len, SEPS, sizeof(SEPS)) ;
      if (!memcmp(zbuf, axfrok, seppos) && (seppos == zonelen || seppos + 1 == zonelen)) break ;
      axfrok += seppos + 1 ;
      len -= seppos + 1 ;
    }
    if (!len) return 5 ;
  }

  shibari_util_canon_domain(&z, zone) ;

  {
    cdb_find_state state = CDB_FIND_STATE_ZERO ;
    int r = shibari_tdb_read_entry(tdb, &state, &soa, z.s, z.len, SHIBARI_T_SOA, 0, loc, wstamp, 0) ;
    if (r == -1) return 2 ;
    if (!r) return 9 ;
  }

  shibari_packet_begin(pkt, qhdr->id, zone, SHIBARI_T_AXFR) ;
  pkt->hdr.aa = 1 ;
  if (!add(b, pkt, &soa, 0, qhdr->id, zone, deadline, stamp)) return -1 ;

  for (;;)
  {
    cdb_data data ;
    int prefixlen ;
    int r = cdb_traverse_next(tdb, &cur.key, &data, &pos) ;
    if (r == -1) return 2 ;
    if (!r) break ;
    prefixlen = shibari_util_get_prefixlen(cur.key.s, cur.key.len, z.s, z.len) ;
    if (prefixlen == -1) continue ;
    r = shibari_tdb_entry_parse(&cur, data.s, data.len, SHIBARI_T_ANY, 2, loc, wstamp) ;
    if (r == -1) return 2 ;
    if (!r) continue ;
    if (cur.type == SHIBARI_T_SOA) continue ;
    if (!add(b, pkt, &cur, prefixlen, qhdr->id, zone, deadline, stamp)) return -1 ;
  }

  if (!add(b, pkt, &soa, 0, qhdr->id, zone, deadline, stamp)) return -1 ;
  shibari_packet_end(pkt) ;
  return 0 ;
}
