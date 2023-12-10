/* ISC license. */

#include <skalibs/uint16.h>
#include <skalibs/strerr.h>

#include <s6-dns/s6dns-message.h>

#include <shibari/util.h>
#include <shibari/log.h>

void shibari_log_answer (uint32_t v, s6dns_message_header_t const *hdr, uint16_t len)
{
  if (v < 2) return ;
  if (hdr->rcode)
  {
    char fmtr[UINT16_FMT] ;
    fmtr[uint16_fmt(fmtr, hdr->rcode)] = 0 ;
    strerr_warni4x("answer ", fmtr, " ", shibari_util_rcode_str(hdr->rcode)) ;
  }
  else
  {
    size_t pos = 0 ;
    char fmt[UINT16_FMT << 2] ;
    char fmtl[UINT16_FMT] ;
    pos += uint16_fmt(fmt + pos, hdr->counts.qd) ;
    fmt[pos++] = '+' ;
    pos += uint16_fmt(fmt + pos, hdr->counts.an) ;
    fmt[pos++] = '+' ;
    pos += uint16_fmt(fmt + pos, hdr->counts.ns) ;
    fmt[pos++] = '+' ;
    pos += uint16_fmt(fmt + pos, hdr->counts.qd) ;
    fmt[pos] = 0 ;
    fmtl[uint16_fmt(fmtl, len)] = 0 ;
    strerr_warni5x("answer 0 noerror ", fmt, " len ", fmtl, hdr->tc ? " tc" : "") ;
  }
}
