/* ISC license. */

#include <stdint.h>
#include <string.h>

#include <shibari/util.h>

int shibari_util_get_prefixlen (char const *name, uint16_t namelen, char const *zone, uint16_t zonelen)
{
  return
    namelen < zonelen ? -1 :
    memcmp(name + namelen - zonelen, zone, zonelen) ? -1 :
    namelen - zonelen ;
}
