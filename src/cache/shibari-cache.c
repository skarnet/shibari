/* ISC license. */

#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>

#include <skalibs/ip46.h>
#include <skalibs/posixplz.h>
#include <skalibs/uint16.h>
#include <skalibs/uint32.h>
#include <skalibs/types.h>
#include <skalibs/error.h>
#include <skalibs/strerr.h>
#include <skalibs/sgetopt.h>
#include <skalibs/allreadwrite.h>
#include <skalibs/tai.h>
#include <skalibs/socket.h>
#include <skalibs/ip46.h>
#include <skalibs/cdb.h>
#include <skalibs/sig.h>
#include <skalibs/iopause.h>
#include <skalibs/selfpipe.h>

#include <s6/accessrules.h>

#include <shibari/common.h>
#include <shibari/cache.h>

#define USAGE "shibari-cache [ -U ] [ -v verbosity ] [ -d notif ] [ -D cachedumpfile ] [ -w wtimeout ] [ -i rulesdir | -x rulesfile ] ip[_port]..."
#define dieusage() strerr_dieusage(100, USAGE)


static char const *dumpfile = 0 ;


typedef struct shibari_ip4_s shibari_ip4 ;
struct shibari_ip4_s
{
  int fd ;
  char ip[4] ;
} ;

typedef struct shibari_ip6_s shibari_ip6 ;
struct shibari_ip6_s
{
  int fd ;
  char ip[16] ;
} ;

static inline void argv_pass1 (char const *const *argv, unsigned int *n4, unsigned int *n6)
{
  char ip[16] ;
  for (; *argv ; argv++)
    if (ip6_scan(argv, ip))
#ifdef SKALIBS_IPV6_ENABLED
      n6++ ;
#else
      strerr_dief1x(100, "IPv6 listening addresses unsupported on this system") ;
#endif
    else n4++ ;
}

static inline void argv_pass2 (char const *const *argv, shibari_ip4 *ip4, shibari_ip6 *ip6, uint16_t *ports)
{
  unsigned int i4 = 0, i6 = 0 ;
  char ip[16] ;
  size_t len ;
  for (; *argv ; argv++)
  {
    len = ip6_scan(argv, ip) ;
    if (len)
    {
      if (argv[0][len] == '_')
      {
        uint16_t port ;
        if (!uint160_scan(*argv + len + 1))
          strerr_dief
      }
    }
  }
}

static inline void reload_cdbs (void)
{
  cdb newtdb = CDB_ZERO ;
  if (!cdb_init(&newtdb, tdbfile))
  {
    if (verbosity) strerr_warnwu2sys("reopen DNS data file ", tdbfile) ;
  }
  else
  {
    cdb_free(&tdb) ;
    tdb = newtdb ;
  }
  if (rulestype == 2)
  {
    cdb newrules = CDB_ZERO ;
    if (!cdb_init(&newrules, rulesfile))
    {
      if (verbosity) strerr_warnwu2sys("reopen access rules file ", rulesfile) ;
    }
    else
    {
      cdb_free(&rules) ;
      rules = newrules ;
    }
  }
}

static int check_rules (ip46 const *remoteip, s6_accessrules_params_t *params, char const **loc)
{
  s6_accessrules_result_t r ;
  params->env.len = 0 ;
  params->exec.len = 0 ;
  r = rulestype == 2 ?
    s6_accessrules_ip46_cdb(remoteip, &rules, params) :
    s6_accessrules_ip46_fs(remoteip, rulesfile, params) ;
  if (r != S6_ACCESSRULES_ALLOW) return 0 ;

  if (params->env.len)
  {
    char const *p ;
    if (params->env.s[params->env.len - 1])
    {
      if (verbosity)
      {
        char fmt[IP46_FMT] ;
        fmt[ip46_fmt(fmt, remoteip)] = 0 ;
        strerr_warnw6x("invalid environment parameters in rules ", rulestype == 2 ? "cdb " : "directory ", rulesfile, " for ip ", fmt, " - denying connection") ;
      }
      return 0 ;
    }
    p = memmem(params->env.s, params->env.len - 1, VAR "=", sizeof(VAR)) ;
    if (p && (p == params->env.s || !p[-1])) *loc = p + sizeof(VAR) ;
  }
  return 1 ;
}

static inline void handle_signals (void)
{
  for (;;) switch (selfpipe_read())
  {
    case -1 : strerr_diefu1sys(111, "read selfpipe") ;
    case 0 : return ;
    case SIGTERM : cont = 0 ; break ;
    case SIGHUP : reload_cdbs() ; break ;
    case SIGALRM : dump_cache() ; break ;
    default : break ;
  }
}

int main (int argc, char const *const *argv)
{
  unsigned int notif = 0 ;
  unsigned int n4 = 0, n6 = 0 ;
  uid_t uid = 0 ;
  gid_t gid = 0 ;
  PROG = "shibari-cache" ;
  {
    int flagdrop = 0 ;
    subgetopt l = SUBGETOPT_ZERO ;
    for (;;)
    {
      int opt = subgetopt_r(argc, argv, "Uv:d:D:w:i:x:", &l) ;
      if (opt == -1) break ;
      switch (opt)
      {
        case 'U' : flagdrop = 1 ; break ;
        case 'v' : if (!uint320_scan(l.arg, &verbosity)) dieusage() ; break ;
        case 'd' : if (!uint0_scan(l.arg, &notif)) dieusage() ; break ;
        case 'D' : dumpfile = l.arg ; break ;
        case 'w' : if (!uint0_scan(l.arg, &wtimeout)) dieusage() ; break ;
        case 'i' : rulesfile = l.arg ; rulestype = 1 ; break ;
        case 'x' : rulesfile = l.arg ; rulestype = 2 ; break ;
        default : strerr_dieusage(10, USAGE) ;
      }
    }
    argc -= l.ind ; argv += l.ind ;
    if (!argc) default_iplist ;

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
  x[0].fd = selfpipe_init() ;
  if (x[0].fd == -1) strerr_diefu1sys(111, "create selfpipe") ;
  if (!sig_altignore(SIGPIPE)) strerr_diefu1sys(111, "ignore SIGPIPE") ;
  {
    sigset_t set ;
    sigemptyset(&set) ;
    sigaddset(&set, SIGHUP) ;
    sigaddset(&set, SIGTERM) ;
    if (!selfpipe_trapset(&set)) strerr_diefu1sys(111, "trap signals") ;
  }

  if (!cdb_init(&tdb, tdbfile)) strerr_diefu2sys(111, "open cdb file ", tdbfile) ;
  if (rulestype == 2 && !cdb_init(&rules, rulesfile)) strerr_diefu2sys(111, "open rules file ", rulesfile) ;

  x[1].fd = socket_udp46_nb(ip46_is6(&localip)) ;
  if (x[1].fd == -1) strerr_diefu1sys(111, "create socket") ;
  if (socket_bind46_reuse(x[1].fd, &localip, localport) == -1) strerr_diefu1sys(111, "bind socket") ;

  if (gid && setgid(gid) == -1) strerr_diefu1sys(111, "setgid") ;
  if (uid && setuid(uid) == -1) strerr_diefu1sys(111, "setuid") ;
  if (!tain_now_set_stopwatch_g()) strerr_diefu1sys(111, "initialize clock") ;

  shibari_log_start(verbosity, &localip, localport) ;
  if (notif)
  {
    write(notif, "\n", 1) ;
    close(notif) ;
  }

  while (cont)
  {
    tain wstamp = TAIN_INFINITE ;
    char const *loc = 0 ;
    s6dns_message_header_t hdr ;
    s6dns_message_counts_t counts ;
    s6dns_domain_t name ;
    unsigned int rcode ;
    ssize_t r ;
    uint16_t qtype ;
    uint16_t remoteport ;
    ip46 remoteip ;

    if (iopause_g(x, 2, &wstamp) == -1) strerr_diefu1sys(111, "iopause") ;
    if (x[0].revents & IOPAUSE_EXCEPT) strerr_dief1x(111, "trouble with selfpipe") ;
    if (x[0].revents & IOPAUSE_READ) { handle_signals() ; continue ; }

    r = sanitize_read(socket_recv46(x[1].fd, buf, 512, &remoteip, &remoteport, ip46_is6(&localip))) ;
    if (!r) continue ;
    if (r == -1) strerr_diefu1sys(111, "recv from socket") ;
    if (rulestype && !check_rules(&remoteip, &params, &loc)) continue ;
    if (!s6dns_message_parse_init(&hdr, &counts, buf, r, &rcode)) continue ;
    if (hdr.opcode) { rcode = 4 ; goto answer ; }
    if (!s6dns_message_parse_question(&counts, &name, &qtype, buf, r, &rcode) || !s6dns_domain_encode(&name))
    {
      rcode = errno == ENOTSUP ? 4 : 1 ;
      goto answer ;
    }
    shibari_log_queryplus(verbosity, &name, qtype, &remoteip, remoteport) ;
    tain_wallclock_read(&wstamp) ;
    rcode = shibari_packet_tdb_answer_query(&pkt, &tdb, &hdr, &name, qtype, loc, &wstamp) ;

 answer:
    if (rcode && rcode != 3)
    {
      shibari_packet_begin(&pkt, hdr.id, &name, qtype) ;
      pkt.hdr.rcode = rcode ;
      shibari_packet_end(&pkt) ;
    }
    shibari_log_answer(verbosity, &pkt.hdr, pkt.pos) ;
    tain_add_g(&wstamp, &wtto) ;
    if (socket_sendnb46_g(x[1].fd, buf, pkt.pos, &remoteip, remoteport, &wstamp) < pkt.pos && verbosity)
      strerr_warnwu1sys("send answer") ;
  }

  shibari_log_exit(verbosity, 0) ;
  return 0 ;
}
