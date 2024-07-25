/* ISC license. */

#include <stddef.h>
#include <errno.h>
#include <string.h>

#include <skalibs/uint16.h>
#include <skalibs/uint32.h>
#include <skalibs/uint64.h>
#include <skalibs/cdb.h>

#include "shibari-cache-internal.h"

#include <skalibs/posixishard.h>

int conf_getb (char const *key, size_t keylen, cdb_data *data)
{
  if (keylen > 4096) return (errno = EINVAL, 0) ;
  switch (cdb_find(&g->confdb, data, key, keylen))
  {
    case -1 : return (errno = EILSEQ, 0) ;
    case 0 : return (errno = ENOENT, 0) ;
    default : return 1 ;
  }
}

int conf_get (char const *key, cdb_data *data)
{
  return conf_getb(key, strlen(key), data) ;
}

int conf_get_uint16 (char const *key, uint16_t *value)
{
  cdb_data data ;
  if (!conf_get(key, &data)) return 0 ;
  if (data.len != 2) return (errno = EPROTO, 0) ;
  uint16_unpack_big(data.s, value) ;
  return 1 ;
}

int conf_get_uint32 (char const *key, uint32_t *value)
{
  cdb_data data ;
  if (!conf_get(key, &data)) return 0 ;
  if (data.len != 4) return (errno = EPROTO, 0) ;
  uint32_unpack_big(data.s, value) ;
  return 1 ;
}

int conf_get_uint64 (char const *key, uint64_t *value)
{
  cdb_data data ;
  if (!conf_get(key, &data)) return 0 ;
  if (data.len != 8) return (errno = EPROTO, 0) ;
  uint64_unpack_big(data.s, value) ;
  return 1 ;
}

char const *conf_get_string (char const *key)
{
  cdb_data data ;
  if (!conf_get(key, &data)) return 0 ;
  if (!data.len || data.s[data.len - 1]) return (errno = EPROTO, NULL) ;
  return data.s ;
}
