/* ISC license. */

#include <skalibs/uint16.h>
#include <skalibs/ip46.h>
#include <skalibs/strerr.h>

#include <s6-dns/s6dns-domain.h>

#include <shibari/util.h>
#include <shibari/log.h>

void shibari_log_queryplus (uint32_t v, s6dns_domain_t const *q, uint16_t qtype, ip46 const *ip, uint16_t port)
{
  char qs[256] ;
  char fmti[IP46_FMT] ;
  char fmtp[UINT16_FMT] ;
  s6dns_domain_t qe ;
  if (v < 2) return ;
  qe = *q ;
  if (!s6dns_domain_encode(&qe) || !s6dns_domain_tostring(qs, 256, &qe)) return ;
  fmti[ip46_fmt(fmti, ip)] = 0 ;
  fmtp[uint16_fmt(fmtp, port)] = 0 ;
  strerr_warni8x("query ", shibari_util_qtype_str(qtype), " ", qs, " ip ", fmti, " port ", fmtp) ;
}
