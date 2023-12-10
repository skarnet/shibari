/* ISC license. */

#include <skalibs/cdb.h>

#include <shibari/constants.h>
#include <shibari/util.h>
#include <shibari/tdb.h>
#include <shibari/packet.h>

static int shibari_packet_add_glue_for_rr (shibari_packet *pkt, cdb const *tdb, char const *s, uint16_t len, uint16_t prefixlen, uint16_t offset, char const *loc, tain const *stamp)
{
  cdb_find_state state = CDB_FIND_STATE_ZERO ;
  for (;;)
  {
    shibari_tdb_entry entry ;
    int r = shibari_tdb_read_entry(tdb, &state, &entry, s, len, SHIBARI_T_ANY, 0, loc, stamp, 0) ;
    if (r == -1) return 2 ;
    if (!r) break ;
    if (entry.type != SHIBARI_T_A && entry.type != SHIBARI_T_AAAA) continue ;
    if (!shibari_packet_add_rr(pkt, &entry, prefixlen, offset, 4))
    {
      pkt->hdr.tc = 1 ;
      return 0 ;
    }
  }
  return -1 ;
}

unsigned int shibari_packet_add_glue (shibari_packet *pkt, cdb const *tdb, char const *s, uint16_t len, uint16_t qtype, char const *z, uint16_t zlen, uint16_t zoffset, uint16_t wildpos, char const *loc, tain const *stamp)
{
  cdb_find_state state = CDB_FIND_STATE_ZERO ;
  for (;;)
  {
    shibari_tdb_entry entry ;
    cdb_data domain ;
    int zprefixlen, sprefixlen ;
    int r = shibari_tdb_read_entry(tdb, &state, &entry, s + wildpos, len - wildpos, qtype, !!wildpos, loc, stamp, 0) ;
    if (r == -1) return 2 ;
    if (!r) break ;
    if (!shibari_tdb_extract_domain(&entry, &domain)) continue ;
    zprefixlen = shibari_util_get_prefixlen(domain.s, domain.len, z, zlen) ;
    if (zprefixlen == -1) continue ;
    sprefixlen = shibari_util_get_prefixlen(domain.s, domain.len, s, len) ;
    r = shibari_packet_add_glue_for_rr(pkt, tdb, domain.s, domain.len, sprefixlen == -1 ? zprefixlen : sprefixlen, sprefixlen == -1 ? zoffset : 0, loc, stamp) ;
    if (r >= 0) return r ;
  }
  return 0 ;
}
