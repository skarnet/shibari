/* ISC license. */

#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>

#include <skalibs/uint16.h>
#include <skalibs/uint32.h>
#include <skalibs/types.h>
#include <skalibs/bytestr.h>
#include <skalibs/strerr.h>
#include <skalibs/buffer.h>
#include <skalibs/sgetopt.h>
#include <skalibs/sig.h>
#include <skalibs/tai.h>
#include <skalibs/djbunix.h>
#include <skalibs/ip46.h>
#include <skalibs/cdb.h>
#include <skalibs/unix-timed.h>

#include <s6-dns/s6dns-domain.h>
#include <s6-dns/s6dns-message.h>

#include <shibari/common.h>
#include <shibari/server.h>

#define PROGNAME "shibari-server-tcp"
#define USAGE PROGNAME " [ -v verbosity ] [ -f cdbfile ] [ -r timeout ] [ -w timeout ]"
#define dieusage() strerr_dieusage(100, USAGE)

#define QMAX 2048
#define RMAX 65535

static uint32_t verbosity = 1 ;

static inline void get_socket_info (ip46 *localip, uint16_t *localport, ip46 *remoteip, uint16_t *remoteport)
{
  char const *x = getenv("PROTO") ;
  if (!x) strerr_dienotset(100, "PROTO") ;
  {
    size_t protolen = strlen(x) ;
    char var[protolen + 11] ;
    memcpy(var, x, protolen) ;
    memcpy(var + protolen, "LOCALIP", 8) ;
    x = getenv(var) ;
    if (!x) strerr_dienotset(100, var) ;
    if (!ip46_scan(x, localip)) strerr_dieinvalid(100, var) ;
    memcpy(var + protolen + 5, "PORT", 5) ;
    x = getenv(var) ;
    if (!x) strerr_dienotset(100, var) ;
    if (!uint160_scan(x, localport)) strerr_dieinvalid(100, var) ;
    memcpy(var + protolen, "REMOTEIP", 9) ;
    x = getenv(var) ;
    if (!x) strerr_dienotset(100, var) ;
    if (!ip46_scan(x, remoteip)) strerr_dieinvalid(100, var) ;
    memcpy(var + protolen + 6, "PORT", 5) ;
    x = getenv(var) ;
    if (!x) strerr_dienotset(100, var) ;
    if (!uint160_scan(x, remoteport)) strerr_dieinvalid(100, var) ;
  }
}

static void add (shibari_packet *pkt, shibari_tdb_entry const *entry, int prefixlen, uint16_t id, s6dns_domain_t const *zone, tain const *deadline)
{
  if (!shibari_packet_add_rr(pkt, entry, prefixlen, 0, 2))
  {
    shibari_packet_end(pkt) ;
    if (!buffer_timed_put_g(buffer_1, pkt->buf - 2, pkt->pos + 2, deadline))
      strerr_diefu1sys(111, "write to stdout") ;
    shibari_packet_begin(pkt, id, zone, SHIBARI_T_AXFR) ;
    if (!shibari_packet_add_rr(pkt, entry, prefixlen, 0, 2))
      strerr_dief1x(101, "can't happen: record too long to fit in single packet") ;
  }
}

#define SEPS "/,; \t\n"

static inline int axfr (char const *axfrok, char const *loc, cdb const *tdb, s6dns_message_header_t const *qhdr, s6dns_domain_t const *zone, shibari_packet *pkt, tain const *deadline, tain const *wstamp)
{
  shibari_tdb_entry soa ;
  shibari_tdb_entry cur ;
  uint32_t pos = CDB_TRAVERSE_INIT() ;
  if (axfrok && axfrok[0] != '*')
  {
    s6dns_domain_t decoded = *zone ;
    unsigned int zonelen ;
    size_t len = strlen(axfrok) + 1 ;
    char zbuf[256] ;
    if (!s6dns_domain_decode(&decoded)) return 1 ;
    zonelen = s6dns_domain_tostring(zbuf, 256, &decoded) ;
    while (len)
    {
      size_t seppos = byte_in(axfrok, len, SEPS, sizeof(SEPS)) ;
      if (!memcmp(zbuf, axfrok, seppos) && (seppos == zonelen || seppos + 1 == zonelen)) break ;
      axfrok += seppos + 1 ;
      len -= seppos + 1 ;
    }
    if (!len) return 5 ;
  }

  {
    cdb_find_state state = CDB_FIND_STATE_ZERO ;
    int r = shibari_tdb_read_entry(tdb, &state, &soa, zone->s, zone->len, SHIBARI_T_SOA, 0, loc, wstamp, 0) ;
    if (r == -1) return 2 ;
    if (!r) return 9 ;
  }

  shibari_packet_begin(pkt, qhdr->id, zone, SHIBARI_T_AXFR) ;
  pkt->hdr.aa = 1 ;
  add(pkt, &soa, 0, qhdr->id, zone, deadline) ;

  for (;;)
  {
    cdb_data data ;
    int prefixlen ;
    int r = cdb_traverse_next(tdb, &cur.key, &data, &pos) ;
    if (r == -1) return 2 ;
    if (!r) break ;
    prefixlen = shibari_util_get_prefixlen(cur.key.s, cur.key.len, zone->s, zone->len) ;
    if (prefixlen == -1) continue ;
    r = shibari_tdb_entry_parse(&cur, data.s, data.len, SHIBARI_T_ANY, 2, loc, wstamp) ;
    if (r == -1) return 2 ;
    if (!r) continue ;
    if (cur.type == SHIBARI_T_SOA) continue ;
    add(pkt, &cur, prefixlen, qhdr->id, zone, deadline) ;
  }

  add(pkt, &soa, 0, qhdr->id, zone, deadline) ;
  shibari_packet_end(pkt) ;
  return 0 ;
}

int main (int argc, char const *const *argv)
{
  cdb tdb = CDB_ZERO ;
  char const *axfrok = getenv("AXFR") ;
  char const *loc = getenv("LOC") ;
  tain rtto = TAIN_INFINITE_RELATIVE, wtto = TAIN_INFINITE_RELATIVE ;
  ip46 localip, remoteip ;
  uint16_t localport, remoteport ;
  char progbuf[sizeof(PROGNAME) + 5 + PID_FMT] = PROGNAME ": pid " ;
  char buf[RMAX + 2] ;
  shibari_packet pkt = SHIBARI_PACKET_INIT(buf, RMAX + 2, 1) ;
  PROG = "shibari-server-tcp" ;

  {
    size_t pos = sizeof(PROGNAME) + 5 ;
    pos += pid_fmt(progbuf + pos, getpid()) ;
    progbuf[pos++] = 0 ;
  }

  {
    char const *tdbfile = "data.cdb" ;
    uint32_t r = 0, w = 0 ;
    subgetopt l = SUBGETOPT_ZERO ;
    for (;;)
    {
      int opt = subgetopt_r(argc, argv, "v:f:r:w:", &l) ;
      if (opt == -1) break ;
      switch (opt)
      {
        case 'v' : if (!uint320_scan(l.arg, &verbosity)) dieusage() ; break ;
        case 'f' : tdbfile = l.arg ; break ;
        case 'r' : if (!uint320_scan(l.arg, &r)) dieusage() ; break ;
        case 'w' : if (!uint320_scan(l.arg, &w)) dieusage() ; break ;
        default :  dieusage() ;
      }
    }
    argc -= l.ind ; argv += l.ind ;
    if (r) tain_from_millisecs(&rtto, r) ;
    if (w) tain_from_millisecs(&wtto, w) ;
    get_socket_info(&localip, &localport, &remoteip, &remoteport) ;
    PROG = progbuf ;
    if (!cdb_init(&tdb, tdbfile)) strerr_diefu2sys(111, "open DNS database file ", tdbfile) ;
  }

  if (ndelay_on(0) == -1 || ndelay_on(1) == -1)
    strerr_diefu1sys(111, "set socket nonblocking") ;
  if (!sig_altignore(SIGPIPE)) strerr_diefu1sys(111, "ignore SIGPIPE") ;
  tain_now_set_stopwatch_g() ;
  shibari_log_start(verbosity, &remoteip, remoteport) ;

  for (;;)
  {
    tain wstamp ;
    size_t w ;
    tain deadline ;
    s6dns_message_header_t hdr ;
    s6dns_message_counts_t counts ;
    s6dns_domain_t name ;
    unsigned int rcode ;
    uint16_t qtype ;
    uint16_t len ;
    tain_add_g(&deadline, &rtto) ;
    w = buffer_timed_get_g(buffer_0, buf, 2, &deadline) ;
    if (w == 1) strerr_dief1x(1, "invalid request") ;
    if (!w)
    {
      if (errno && errno != EPIPE && errno != ETIMEDOUT)
        strerr_diefu1sys(111, "read from stdin") ;
      else break ;
    }
    uint16_unpack_big(buf, &len) ;
    if (len > QMAX) strerr_dief1x(1, "request too large") ;
    if (buffer_timed_get_g(buffer_0, buf, len, &deadline) < len)
      strerr_diefu1sys(111, "read from stdin") ;

    if (!s6dns_message_parse_init(&hdr, &counts, buf, len, &rcode))
      strerr_diefu1sys(111, "parse message") ;
    if (hdr.opcode) { rcode = 4 ; goto answer ; }
    if (!s6dns_message_parse_question(&counts, &name, &qtype, buf, len, &rcode) || !s6dns_domain_encode(&name))
    {
      rcode = errno == ENOTSUP ? 4 : 1 ;
      goto answer ;
    }
    shibari_log_query(verbosity, &name, qtype) ;
    tain_add_g(&deadline, &wtto) ;
    tain_wallclock_read(&wstamp) ;
    rcode = qtype == SHIBARI_T_AXFR ?
      axfr(axfrok, loc, &tdb, &hdr, &name, &pkt, &deadline, &wstamp) :
      shibari_packet_tdb_answer_query(&pkt, &tdb, &hdr, &name, qtype, loc, &wstamp) ;

 answer:
    if (rcode && rcode != 3)
    {
      shibari_packet_begin(&pkt, hdr.id, &name, qtype) ;
      pkt.hdr.rcode = rcode ;
      shibari_packet_end(&pkt) ;
    }
    shibari_log_answer(verbosity, &pkt.hdr, pkt.pos) ;
    if (!buffer_timed_put_g(buffer_1, buf, pkt.pos + 2, &deadline)
     || !buffer_timed_flush_g(buffer_1, &deadline))
      strerr_diefu1sys(111, "write to stdout") ;
  }

  shibari_log_exit(verbosity, 0) ;
  return 0 ;
}
