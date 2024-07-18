/* ISC license. */

#include <stdint.h>

#include <skalibs/cdb.h>

#include "shibari-cache-internal.h"

static inline int check (char const *key, size_t keylen)
{
  cdb_data data ;
  return cdb_find(&confdb, &data, key, keylen) ;
}

int ip4_access (char const *ip)
{
  int r ;
  char key[9] = "A4:" ;
  uint8_t i = 33 ;
  memcpy(key+4, ip, 4) ;
  key[8] = 0 ;
  while (i--)
  {
    key[3] = i ;
    key[4 + (i>>3)] &= ~(1U << (7 - (i & 7))) ;
    r = check(key, 8) ;
    if (r) return r ;
  }
  return 0 ;
}

int ip6_access (char const *ip)
{
  int r ;
  char key[21] = "A6:" ;
  uint8_t i = 129 ;
  memcpy(key+4, ip, 16) ;
  key[20] = 0 ;
  while (i--)
  {
    key[3] = i ;
    key[4 + (i>>3)] &= ~(1U << (7 - (i & 7))) ;
    r = check(key, 20) ;
    if (r) return r ;
  }
  return 0 ;
}
