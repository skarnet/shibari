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
#include <skalibs/error.h>
#include <skalibs/strerr.h>
#include <skalibs/sgetopt.h>
#include <skalibs/tai.h>
#include <skalibs/socket.h>
#include <skalibs/ip46.h>
#include <skalibs/cdb.h>
#include <skalibs/sig.h>

#include <s6/accessrules.h>

#include <shibari/common.h>
#include <shibari/server.h>

#define USAGE "shibari-server-udp [ -v verbosity ] [ -d notif ] [ -f cdbfile ] [ -i rulesdir | -x rulesfile ] [ -p port ] ip"
#define dieusage() strerr_dieusage(100, USAGE)

#define VAR "LOC"

static char const *tdbfile = "data.cdb" ;
static cdb tdb = CDB_ZERO ;
static cdb rules = CDB_ZERO ;
static char const *rulesfile = 0 ;
static unsigned int rulestype = 0 ;
static int cont = 1 ;
static uint32_t verbosity = 1 ;

static void on_term (int s)
{
  (void)s ;
  cont = 0 ;
}

static void on_hup (int s)
{
  cdb newtdb = CDB_ZERO ;
  (void)s ;
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

int main (int argc, char const *const *argv)
{
  s6_accessrules_params_t params = S6_ACCESSRULES_PARAMS_ZERO ;
  int s ;
  unsigned int notif = 0 ;
  char buf[512] ;
  shibari_packet pkt = SHIBARI_PACKET_INIT(buf, 512, 0) ;
  uint16_t localport = 53 ;
  ip46 localip ;

  PROG = "shibari-server-udp" ;

  {
    subgetopt l = SUBGETOPT_ZERO ;
    for (;;)
    {
      int opt = subgetopt_r(argc, argv, "v:d:f:i:x:p:", &l) ;
      if (opt == -1) break ;
      switch (opt)
      {
        case 'v' : if (!uint320_scan(l.arg, &verbosity)) dieusage() ; break ;
        case 'd' : if (!uint0_scan(l.arg, &notif)) dieusage() ; break ;
        case 'f' : tdbfile = l.arg ; break ;
        case 'i' : rulesfile = l.arg ; rulestype = 1 ; break ;
        case 'x' : rulesfile = l.arg ; rulestype = 2 ; break ;
        case 'p' : if (!uint160_scan(l.arg, &localport)) dieusage() ; break ;
        default : strerr_dieusage(10, USAGE) ;
      }
    }
    argc -= l.ind ; argv += l.ind ;
  }

  if (!argc) dieusage() ;
  if (!ip46_scan(argv[0], &localip)) dieusage() ;

  if (notif)
  {
    if (notif < 3) strerr_dief1x(100, "notification fd cannot be 0, 1 or 2") ;
    if (fcntl(notif, F_GETFD) == -1) strerr_diefu1sys(111, "check notification fd") ;
  }

  close(0) ;
  close(1) ;
  s = socket_udp46_b(ip46_is6(&localip)) ;
  if (s == -1) strerr_diefu1sys(111, "create socket") ;
  if (socket_bind46_reuse(s, &localip, localport) == -1) strerr_diefu1sys(111, "bind socket") ;

  if (!cdb_init(&tdb, tdbfile)) strerr_diefu2sys(111, "open cdb file ", tdbfile) ;
  if (rulestype == 2 && !cdb_init(&rules, rulesfile)) strerr_diefu2sys(111, "open rules file ", rulesfile) ;
  if (!sig_catch(SIGHUP, &on_hup)) strerr_diefu1sys(111, "catch SIGHUP") ;
  if (!sig_catch(SIGTERM, &on_term)) strerr_diefu1sys(111, "catch SIGTERM") ;

  shibari_log_start(verbosity, &localip, localport) ;
  if (notif)
  {
    write(notif, "\n", 1) ;
    close(notif) ;
  }

  for (; cont ; sig_unblock(SIGHUP))
  {
    tain wstamp ;
    char const *loc = 0 ;
    s6dns_message_header_t hdr ;
    s6dns_message_counts_t counts ;
    s6dns_domain_t name ;
    unsigned int rcode ;
    ssize_t r ;
    uint16_t qtype ;
    uint16_t remoteport ;
    ip46 remoteip ;

    r = socket_recv46(s, buf, 512, &remoteip, &remoteport) ;
    if (r == -1) strerr_diefu1sys(111, "recv from socket") ;
    if (!r) strerr_dief1x(111, "huh? got EOF on a connection-less socket") ;
    sig_block(SIGHUP) ;
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
    if (socket_send46(s, buf, pkt.pos, &remoteip, remoteport) < pkt.pos && verbosity)
      strerr_warnwu1sys("send answer") ;
  }

  shibari_log_exit(verbosity, 0) ;
  return 0 ;
}
