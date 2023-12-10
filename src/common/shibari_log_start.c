/* ISC license. */

#include <skalibs/uint16.h>
#include <skalibs/ip46.h>
#include <skalibs/strerr.h>

#include <shibari/log.h>

void shibari_log_start (uint32_t v, ip46 const *ip, uint16_t port)
{
  char fmti[IP46_FMT] ;
  char fmtp[UINT16_FMT] ;
  if (v < 2) return ;
  fmti[ip46_fmt(fmti, ip)] = 0 ;
  fmtp[uint16_fmt(fmtp, port)] = 0 ;
  strerr_warni4x("start ip ", fmti, " port ", fmtp) ;
}
