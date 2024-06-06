/* ISC license. */

#include <stdint.h>
#include <ctype.h>

#include <s6-dns/s6dns-domain.h>

#include <shibari/util.h>

void shibari_util_canon_domain (s6dns_domain_t *canon, s6dns_domain_t const *orig)
{
  uint8_t i = 0 ;
  canon->len = orig->len ;
  while (i < orig->len)
  {
    uint8_t len = orig->s[i] ;
    canon->s[i++] = len ;
    for (; len-- ; i++) canon->s[i] = tolower(orig->s[i]) ;
  }
}
