/* ISC license. */

#include <skalibs/strerr.h>

#include <s6-dns/s6dns-domain.h>

#include <shibari/util.h>
#include <shibari/log.h>

void shibari_log_query (uint32_t v, s6dns_domain_t const *q, uint16_t qtype)
{
  char qs[256] ;
  s6dns_domain_t qe ;
  if (v < 2) return ;
  qe = *q ;
  if (!s6dns_domain_decode(&qe) || !s6dns_domain_tostring(qs, 256, &qe)) return ;
  strerr_warni4x("query ", shibari_util_qtype_str(qtype), " ", qs) ;
}
