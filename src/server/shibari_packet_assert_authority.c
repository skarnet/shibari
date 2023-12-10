/* ISC license. */

#include <skalibs/cdb.h>

#include <shibari/constants.h>
#include <shibari/util.h>
#include <shibari/tdb.h>
#include <shibari/packet.h>

unsigned int shibari_packet_assert_authority (shibari_packet *pkt, cdb const *tdb, char const *z, uint16_t zlen, uint16_t zoffset, char const *loc, tain const *stamp)
{
  cdb_find_state state = CDB_FIND_STATE_ZERO ;
  shibari_tdb_entry soa ;
  int r = shibari_tdb_read_entry(tdb, &state, &soa, z, zlen, SHIBARI_T_SOA, 0, loc, stamp, 0) ;
  if (r <= 0) return 2 ;
  if (!shibari_packet_add_rr(pkt, &soa, 0, zoffset, 3)) pkt->hdr.tc = 1 ;
  return 0 ;
}
