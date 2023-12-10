/* ISC license. */

#include <skalibs/cdb.h>

#include <shibari/tdb.h>

int shibari_tdb_read_entry (cdb const *tdb, cdb_find_state *state, shibari_tdb_entry *out, char const *s, uint16_t len, uint16_t qtype, unsigned int wild, char const *loc, tain const *stamp, uint32_t *flags)
{
  cdb_data data ;
  int r = 0 ;
  while (!r)
  {
    r = cdb_findnext(tdb, &data, s, len, state) ;
    if (r <= 0) return r ;
    if (flags) *flags |= 1 ;
    r = shibari_tdb_entry_parse(out, data.s, data.len, qtype, wild, loc, stamp) ;
    if (r == -1) return -1 ;
  }
  out->key.s = s ;
  out->key.len = len ;
  return 1 ;
}
