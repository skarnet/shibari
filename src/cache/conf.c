/* ISC license. */

#include <errno.h>
#include <string.h>

#include <skalibs/uint32.h>
#include <skalibs/uint64.h>
#include <skalibs/cdb.h>

#include "shibari-cache-internal.h"

#include <skalibs/posixishard.h>

int conf_getb (cdb const *c, char const *key, size_t keylen, cdb_data *data)
{
  if (keylen > 4096) return (errno = EINVAL, 0) ;
  switch (cdb_find(c, data, key, keylen))
  {
    case -1 : return (errno = EILSEQ, 0) ;
    case 0 : return (errno = ENOENT, 0) ;
    default : return 1 ;
  }
}

int conf_get (cdb const *c, char const *key, cdb_data *data)
{
  return conf_getb(c, key, strlen(key), data) ;
}

int conf_get_uint32 (cdb const *c, char const *key, uint32_t *value)
{
  cdb_data data ;
  if (!conf_get(conf, key, &data)) return 0 ;
  if (data.len != 4) return (errno = EPROTO, 0) ;
  uint32_unpack_big(data.s, value) ;
  return 1 ;
}

int conf_get_uint64 (cdb const *c, char const *key, uint64_t *value)
{
  cdb_data data ;
  if (!conf_get(conf, key, &data)) return 0 ;
  if (data.len != 8) return (errno = EPROTO, 0) ;
  uint64_unpack_big(data.s, value) ;
  return 1 ;
}

char const *conf_get_string (cdb const *c, char const *key)
{
  cdb_data data ;
  if (!conf_get(conf, key, &data)) return 0 ;
  if (!data.len || data.s[data.len - 1]) return (errno = EPROTO, 0) ;
  return data.s ;
}
