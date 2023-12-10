/* ISC license. */

#include <stdint.h>

#include <skalibs/uint16.h>
#include <skalibs/uint32.h>
#include <skalibs/tai.h>

#include <shibari/constants.h>
#include <shibari/tdb.h>

int shibari_tdb_entry_parse (shibari_tdb_entry *out, char const *s, uint16_t len, uint16_t qtype, unsigned int wild, char const *loc, tain const *stamp)
{
  tai ttd ;
  uint32_t ttl ;
  uint32_t flags = 0 ;
  uint16_t type ;
  if (len < 15) return -1 ;
  uint16_unpack_big(s, &type) ;
  if (qtype != SHIBARI_T_ANY && qtype != type && type != SHIBARI_T_CNAME) return 0 ;
  s += 3 ; len -= 3 ;
  switch (s[-1])
  {
    case '+' : flags |= 1 ;
    case '>' :
      if (len < 14) return -1 ;
      if (loc && loc[0] && (loc[0] != s[0] || loc[1] != s[1])) return 0 ;
      s += 2 ; len -= 2 ;
      break ;
    case '*' : flags |= 1 ;
    case '=' : break ;
    default : return -1 ;
  }
  if (wild < 2 && wild != (flags & 1)) return 0 ;
  uint32_unpack_big(s, &ttl) ;
  s += 4 ; len -= 4 ;
  tai_unpack(s, &ttd) ;
  s += 8 ; len -= 8 ;
  if (tai_sec(&ttd))
  {
    if (!ttl == !tai_less(tain_secp(stamp), &ttd)) return 0 ;
    if (!ttl)
    {
      tai t ;
      tai_sub(&t, &ttd, tain_secp(stamp)) ;
      if (tai_sec(&t) < 2) ttl = 2 ;
      else if (tai_sec(&t) > 3600 && qtype != SHIBARI_T_ANY) ttl = 3600 ;
    }
  }
  out->ttl = ttl ;
  out->flags = flags ;
  out->type = type ;
  out->data.s = s ;
  out->data.len = len ;
  return 1 ;
}
