/* ISC license. */

#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>

#include <skalibs/posixplz.h>
#include <skalibs/uint16.h>
#include <skalibs/uint32.h>
#include <skalibs/types.h>
#include <skalibs/strerr.h>
#include <skalibs/sgetopt.h>
#include <skalibs/tai.h>
#include <skalibs/socket.h>
#include <skalibs/cdb.h>
#include <skalibs/sig.h>
#include <skalibs/iopause.h>
#include <skalibs/selfpipe.h>
#include <skalibs/ip46.h>
#inclide <skalibs/genalloc.h>

#include <shibari/config.h>
#include <shibari/common.h>
#include <shibari/cache.h>

#include "shibari-cache-internal.h"

#define USAGE "shibari-cache [ -U ] [ -d notif ] [ -f conf.cdb ] [ -D cachedumpfile ] [ -w wtimeout ] [ -i rulesdir | -x rulesfile ]"
#define dieusage() strerr_dieusage(100, USAGE)


uint32_t verbosity ;
cdb confdb = CDB_ZERO ;
size_t n4 = 0, n6 = 0, ntcp = 0 ;

static int cont = 1 ;
static int sfd = -1 ;
static char const *dumpfile = 0 ;


static inline void reload (void)
{
}

static inline void handle_signals (void)
{
  for (;;) switch (selfpipe_read())
  {
    case -1 : strerr_diefu1sys(111, "read selfpipe") ;
    case 0 : return ;
    case SIGTERM : cont = 0 ; break ;
    case SIGHUP : reload() ; break ;
    case SIGALRM : dump_cache(dumpfile) ; break ;
    default : break ;
  }
}

int main (int argc, char const *const *argv)
{
  char const *conffile = SHIBARI_SYSCONFDIR "/shibari-cache.conf.cdb" ;
  unsigned int notif = 0 ;
  char const *ip4 ;
  char const *ip6 ;
  uid_t uid = 0 ;
  gid_t gid = 0 ;
  PROG = "shibari-cache" ;
  {
    int flagdrop = 0 ;
    subgetopt l = SUBGETOPT_ZERO ;
    for (;;)
    {
      int opt = subgetopt_r(argc, argv, "Ud:f:D:w:i:x:", &l) ;
      if (opt == -1) break ;
      switch (opt)
      {
        case 'U' : flagdrop = 1 ; break ;
        case 'd' : if (!uint0_scan(l.arg, &notif)) dieusage() ; break ;
        case 'f' : conffile = l.arg ; break ;
        case 'D' : dumpfile = l.arg ; break ;
        case 'w' : if (!uint0_scan(l.arg, &wtimeout)) dieusage() ; break ;
        case 'i' : rulesfile = l.arg ; rulestype = 1 ; break ;
        case 'x' : rulesfile = l.arg ; rulestype = 2 ; break ;
        default : strerr_dieusage(10, USAGE) ;
      }
    }
    argc -= l.ind ; argv += l.ind ;
    if (!ip46_scan(argv[0], &localip)) dieusage() ;
    if (flagdrop)
    {
      char const *x = getenv("UID") ;
      if (!x) strerr_dienotset(100, "UID") ;
      if (!uid0_scan(x, &uid)) strerr_dieinvalid(100, "UID") ;
      x = getenv("GID") ;
      if (!x) strerr_dienotset(100, "GID") ;
      if (!uid0_scan(x, &gid)) strerr_dieinvalid(100, "GID") ;
    }
    if (wtimeout) tain_from_millisecs(&wtto, wtimeout) ;
  }

  if (notif)
  {
    if (notif < 3) strerr_dief1x(100, "notification fd cannot be 0, 1 or 2") ;
    if (fcntl(notif, F_GETFD) == -1) strerr_diefu1sys(111, "check notification fd") ;
  }

  close(0) ;
  close(1) ;
  sfd = selfpipe_init() ;
  if (sfd == -1) strerr_diefu1sys(111, "create selfpipe") ;
  if (!sig_altignore(SIGPIPE)) strerr_diefu1sys(111, "ignore SIGPIPE") ;
  {
    sigset_t set ;
    sigemptyset(&set) ;
    sigaddset(&set, SIGHUP) ;
    sigaddset(&set, SIGTERM) ;
    sigaddset(&set, SIGALRM) ;
    if (!selfpipe_trapset(&set)) strerr_diefu1sys(111, "trap signals") ;
  }

  if (!cdb_init(&confdb, conffile)) strerr_diefu2sys(111, "open cdb file ", conffile) ;

  {
    cdb_data data ;
    if (!conf_get_uint32(&confdb, "G:logv", &verbosity))
      strerr_diefu1sys(111, "read verbosity from config") ;
    if (!conf_get_uint32(&confdb, "G:maxtcp", &maxtcp))
      strerr_diefu1sys(111, "read maxtcp from config") ;
    if (maxtcp > 4000 || maxtcp < 1)
      strerr_dief1x(102, "invalid maxtcp in config") ;
    if (!conf_get(&confdb, "G:listen4", &data))
      strerr_diefu3sys(111, "read ", "G:listen4", " entry from config") ;
    if (data.len & 3)
      strerr_diefu2sys(102, "invalid length for ", "G:listen4") ;
    n4 = data.len >> 2 ;
    ip4 = data.s ;
#ifdef SKALIBS_IPV6_ENABLED
    if (!conf_get(&confdb, "G:listen6", &data))
      strerr_diefu3sys(111, "read ", "G:listen6", " entry from config") ;
    if (data.len & 15)
      strerr_diefu2sys(102, "invalid length for ", "G:listen6") ;
    n6 = data.len >> 4 ;
    ip6 = data.s ;
#endif
  }
  if (!n4 && !n6) strerr_diefu1x(102, "no listen addresses configured" ;

  {
    genalloc queries = GENALLOC_ZERO ; /* query */
    int fd4[n4 ? n4 : 1][2] ;
    int fd6[n6 ? n6 : 1][2] ;
    tcpconnection tcpconn_storage[maxtcp] ;
    uint32_t tcpconn_freelist[maxtcp] ;
    genset tcpconn_genset ;
    tcpconn = &tcpconn_genset ;
    GENSET_init(tcpconn, tcpconnection, tcpconn_storage, tcpconn_freelist, maxtcp) ;

    for (size_t i = 0 ; i < n4 ; i++)
    {
      fd4[i][0] = socket_udp4_nbcoe() ;
      if (fd4[i][0] == -1) strerr_diefu1sys(111, "create udp4 socket") ;
      if (socket_bind4_reuse(fd4[i][0], ip4 + (i << 2), 53) == -1)
      {
        char fmt[IP4_FMT] ;
        fmt[ip4_fmt(fmt, ip4 + (i << 2))] = 0 ;
        strerr_diefu3sys(111, "bind to ip ", fmt, " UDP port 53") ;
      }
      fd4[i][1] = socket_tcp4_nbcoe() ;
      if (fd4[i][1] == -1) strerr_diefu1sys(111, "create tcp4 socket") ;
      if (socket_bind4_reuse(fd4[i][1], ip4 + (i << 2), 53) == -1)
      {
        char fmt[IP4_FMT] ;
        fmt[ip4_fmt(fmt, ip4 + (i << 2))] = 0 ;
        strerr_diefu3sys(111, "bind to ip ", fmt, " TCP port 53") ;
      }
    }
#ifdef SKALIBS_IPV6_ENABLED
    for (size_t i = 0 ; i < n6 ; i++)
    {
      fd6[i][0] = socket_udp6_nbcoe() ;
      if (fd6[i][0] == -1) strerr_diefu1sys(111, "create udp6 socket") ;
      if (socket_bind6_reuse(fd6[i][0], ip6 + (i << 4), 53) == -1)
      {
        char fmt[IP6_FMT] ;
        fmt[ip6_fmt(fmt, ip6 + (i << 4))] = 0 ;
        strerr_diefu3sys(111, "bind to ip ", fmt, " UDP port 53") ;
      }
      fd6[i][1] = socket_tcp6_nbcoe() ;
      if (fd6[i][1] == -1) strerr_diefu1sys(111, "create tcp6 socket") ;
      if (socket_bind4_reuse(fd6[i][1], ip6 + (i << 4), 53) == -1)
      {
        char fmt[IP6_FMT] ;
        fmt[ip6_fmt(fmt, ip6 + (i << 4))] = 0 ;
        strerr_diefu3sys(111, "bind to ip ", fmt, " TCP port 53") ;
      }
    }
#endif

    if (gid && setgid(gid) == -1) strerr_diefu1sys(111, "setgid") ;
    if (uid && setuid(uid) == -1) strerr_diefu1sys(111, "setuid") ;
    if (!tain_now_set_stopwatch_g()) strerr_diefu1sys(111, "initialize clock") ;

    if (notif)
    {
      write(notif, "\n", 1) ;
      close(notif) ;
    }

    while (cont)
    {
      size_t n = genalloc_len(query, &queries) ;
      iopause_fd x[1 + n4 + n6 + n] ;
      x[0].fd = sfd ;
      x[0].events = IOPAUSE_READ ;
      for (size_t i = 0 ; i < n4 ; i++)
      {
      }
    }

  }
  shibari_log_exit(verbosity, 0) ;
  return 0 ;
}
