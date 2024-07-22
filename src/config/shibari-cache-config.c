/* ISC license. */

#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>  /* rename() */
#include <errno.h>
#include <signal.h>

#include <skalibs/posixplz.h>
#include <skalibs/types.h>
#include <skalibs/sgetopt.h>
#include <skalibs/buffer.h>
#include <skalibs/strerr.h>
#include <skalibs/djbunix.h>

#include <shibari/config.h>
#include "shibari-cache-config-internal.h"

#define USAGE "shibari-cache-config [ -i textfile ] [ -o cdbfile ] [ -m mode ]"
#define dieusage() strerr_dieusage(100, USAGE)

repo conf = REPO_ZERO ;

static inline void conf_output (char const *ofile, unsigned int omode)
{
  int fdw ;
  cdbmaker cm = CDBMAKER_ZERO ;
  size_t olen = strlen(ofile) ;
  char otmp[olen + 8] ;
  memcpy(otmp, ofile, olen) ;
  memcpy(otmp + olen, ":XXXXXX", 8) ;
  fdw = mkstemp(otmp) ;
  if (fdw == -1) strerr_diefu3sys(111, "open ", otmp, " for writing") ;
  if (!cdbmake_start(&cm, fdw))
  {
    unlink_void(otmp) ;
    strerr_diefu2sys(111, "cdmake_start ", otmp) ;
  }
  if (!repo_write(&cm, &conf))
  {
    unlink_void(otmp) ;
    strerr_diefu2sys(111, "write config tree into ", otmp) ;
  }
  if (!cdbmake_finish(&cm))
  {
    unlink_void(otmp) ;
    strerr_diefu2sys(111, "cdbmake_finish ", otmp) ;
  }
  if (fsync(fdw) == -1)
  {
    unlink_void(otmp) ;
    strerr_diefu2sys(111, "fsync ", otmp) ;
  }
  if (fchmod(fdw, omode & 0777) == -1)
  {
    unlink_void(otmp) ;
    strerr_diefu2sys(111, "fchmod ", otmp) ;
  }
  if (rename(otmp, ofile) == -1)
  {
    unlink_void(otmp) ;
    strerr_diefu4sys(111, "rename ", otmp, " to ", ofile) ;
  }
}

int main (int argc, char const *const *argv, char const *const *envp)
{
  char const *ifile = SHIBARI_SYSCONFPREFIX "shibari-cache.conf" ;
  char const *ofile = SHIBARI_SYSCONFPREFIX "shibari-cache.conf.cdb" ;
  unsigned int omode = 0644 ;

  PROG = "shibari-cache-config" ;
  {
    subgetopt l = SUBGETOPT_ZERO ;
    for (;;)
    {
      int opt = subgetopt_r(argc, argv, "i:o:m:", &l) ;
      if (opt == -1) break ;
      switch (opt)
      {
        case 'i' : ifile = l.arg ; break ;
        case 'o' : ofile = l.arg ; break ;
        case 'm' : if (!uint0_oscan(l.arg, &omode)) dieusage() ; break ;
        default : strerr_dieusage(100, USAGE) ;
      }
    }
    argc -= l.ind ; argv += l.ind ;
  }

  repo_init(&conf) ;

  {
    int fdr = openc_readb(ifile) ;
    char buf[4096] ;
    buffer b = BUFFER_INIT(&buffer_read, fdr, buf, 4096) ;
    if (fdr == -1) strerr_diefu2sys(111, "open ", ifile) ;
    conf_lexparse(&b, ifile) ;
  }
  conf_defaults() ;
  conf_output(ofile, omode) ;
  return 0 ;
}
