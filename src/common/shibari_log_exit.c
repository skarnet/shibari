/* ISC license. */

#include <skalibs/types.h>
#include <skalibs/strerr.h>

#include <shibari/log.h>

void shibari_log_exit (uint32_t v, int e)
{
  char fmt[UINT_FMT] ;
  if (v < 2) return ;
  fmt[uint_fmt(fmt, (unsigned int)e)] = 0 ;
  strerr_warni2x("exit ", fmt) ;
}
