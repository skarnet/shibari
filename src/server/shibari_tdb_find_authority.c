/* ISC license. */

#include <stdint.h>

#include <skalibs/cdb.h>

#include <shibari/constants.h>
#include <shibari/tdb.h>

static int find_ns_and_soa (cdb const *tdb, char const *s, uint16_t len, char const *loc, tain const *stamp)
{
  cdb_find_state state = CDB_FIND_STATE_ZERO ;
  unsigned int flags = 0 ;
  for (;;)
  {
    shibari_tdb_entry entry ;
    cdb_data data ;
    int r = cdb_findnext(tdb, &data, s, len, &state) ;
    if (r == -1) return -1 ;
    if (!r) break ;
    r = shibari_tdb_entry_parse(&entry, data.s, data.len, SHIBARI_T_ANY, 0, loc, stamp) ;
    if (r == -1) return -1 ;
    if (!r) continue ;
    if (entry.type == SHIBARI_T_SOA) flags |= 1 ;
    else if (entry.type == SHIBARI_T_NS) flags |= 2 ;
  }
  return flags ;
}

int shibari_tdb_find_authority (cdb const *tdb, char const *s, uint16_t len, char const *loc, tain const *stamp, int *npl)
{
  uint16_t pos = 0 ;
  uint16_t zplen = 0 ;
  int nplen = -1 ;
  while (pos < len)
  {
    int flags = find_ns_and_soa(tdb, s + pos, len - pos, loc, stamp) ;
    if (flags == -1) return -1 ;
    if (flags & 2) nplen = pos ;
    if (flags & 1) { zplen = pos ; break ; }
    pos += 1 + (uint8_t)s[pos] ;
  }
  if (pos >= len) return -2 ;  /* out of bailiwick */
  *npl = nplen ;
  return zplen ;
}
