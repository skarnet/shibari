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
#include <skalibs/uint64.h>
#include <skalibs/types.h>
#include <skalibs/fmtscan.h>
#include <skalibs/error.h>
#include <skalibs/strerr.h>
#include <skalibs/sgetopt.h>
#include <skalibs/allreadwrite.h>
#include <skalibs/tai.h>
#include <skalibs/socket.h>
#include <skalibs/cdb.h>
#include <skalibs/sig.h>
#include <skalibs/iopause.h>
#include <skalibs/selfpipe.h>
#include <skalibs/ip46.h>
#include <skalibs/genalloc.h>
#include <skalibs/netstring.h>

#include <shibari/config.h>
#include <shibari/common.h>

#include "shibari-cache-internal.h"

#define USAGE "shibari-cache [ -U ] [ -d notif ] [ -f conf.cdb ]"
#define dieusage() strerr_dieusage(100, USAGE)

#define MAXSAME 32

global *g = 0 ;

static tain lameduckt = TAIN_INFINITE_RELATIVE ;
static int flagwantfinaldump = 1 ;
static unsigned int cont = 2 ;


static inline void conf_init (char const *conffile, uint16_t *n4, uint16_t *n6, char const **ip4, char const **ip6, uint16_t *maxtcp, uint16_t *maxqueries)
{
  cdb_data data ;
  uint32_t u ;
  if (!conf_get_uint16("G:logv", &g->verbosity))
    strerr_diefu4sys(102, "read ", "G:logv", " configuration key from ", conffile) ;
  {
    uint64_t cachesize ;
    if (!conf_get_uint64("G:cachesize", &cachesize))
      strerr_diefu4sys(102, "read ", "G:cachesize", " configuration key from ", conffile) ;
    if (cachesize < 4096)
      strerr_dief2x(102, "invalid G:cachesize in ", conffile) ;
    cache_init(cachesize) ;
  }
  if (!conf_get_uint16("G:maxtcp", maxtcp))
    strerr_diefu4sys(102, "read ", "G:maxtcp", " configuration key from ", conffile) ;
  if (*maxtcp > 4096 || *maxtcp < 1)
    strerr_dief2x(102, "invalid G:maxtcp in ", conffile) ;
  if (!conf_get_uint16("G:maxqueries", maxqueries))
    strerr_diefu4sys(102, "read ", "G:maxqueries", " configuration key from ", conffile) ;
  if (*maxqueries > 8192 || *maxqueries < 1)
    strerr_dief2x(102, "invalid G:maxqueries in ", conffile) ;
  if (!conf_get_uint32("G:rtimeout", &u))
  if (u) tain_from_millisecs(&g->rtto, u) ;
    strerr_diefu4sys(102, "read ", "G:rtimeout", " configuration key from ", conffile) ;
  if (!conf_get_uint32("G:wtimeout", &u))
    strerr_diefu4sys(102, "read ", "G:wtimeout", " configuration key from ", conffile) ;
  if (u) tain_from_millisecs(&g->wtto, u) ;
  g->dumpfile = conf_get_string("G:cachefile") ;
  if (!g->dumpfile && errno != ENOENT)
    strerr_diefu4sys(102, "read ", "G:cachefile", " configuration key from ", conffile) ;

  if (!conf_get("G:listen4", &data))
    strerr_diefu4sys(102, "read ", "G:listen4", " configuration key from ", conffile) ;
  if (data.len & 3)
    strerr_diefu4sys(102, "invalid ", "G:listen4", " key in ", conffile) ;
  if (data.len > 4 * 1024)
    strerr_diefu3sys(102, "G:listen4", " key too long in ", conffile) ;
  *n4 = data.len >> 2 ;
  *ip4 = data.s ;
#ifdef SKALIBS_IPV6_ENABLED
  if (!conf_get("G:listen6", &data))
    strerr_diefu4sys(102, "read ", "G:listen6", " configuration key from ", conffile) ;
  if (data.len & 15)
    strerr_diefu4sys(102, "invalid ", "G:listen6", " key in ", conffile) ;
  if (data.len > 16 * 1024)
    strerr_diefu3sys(102, "G:listen6", " key too long in ", conffile) ;
  *n6 = data.len >> 4 ;
  *ip6 = data.s ;
#endif
  if (!*n4 && !*n6) strerr_dief1x(102, "no listen addresses configured") ;
}

static inline void handle_signals (void)
{
  for (;;) switch (selfpipe_read())
  {
    case -1 : strerr_diefu1sys(111, "read selfpipe") ;
    case 0 : return ;
    case SIGHUP : flagwantfinaldump = 0 ;  /* fallthrough */
    case SIGTERM :
      if (cont >= 2)
      {
        tain_add_g(&lameduckt, &lameduckt) ;
        cont = 1 ;
      }
      break ;
    case SIGQUIT : cont = 0 ; flagwantfinaldump = 0 ; break ;
    case SIGALRM : cache_dump() ; break ;
    default : break ;
  }
}

int main (int argc, char const *const *argv)
{
  global globals = GLOBAL_ZERO ;
  char const *conffile = SHIBARI_SYSCONFPREFIX "/shibari-cache.conf.cdb" ;
  uint16_t n4 = 0, n6 = 0, maxtcp, maxqueries ;
  char const *ip4 = 0, *ip6 = 0 ;
  unsigned int cont = 2 ;
  int spfd = -1 ;
  unsigned int notif = 0 ;
  uid_t uid = 0 ;
  gid_t gid = 0 ;
  PROG = "shibari-cache" ;
  g = &globals ;
  {
    int flagdrop = 0 ;
    subgetopt l = SUBGETOPT_ZERO ;
    for (;;)
    {
      int opt = subgetopt_r(argc, argv, "Ud:f:", &l) ;
      if (opt == -1) break ;
      switch (opt)
      {
        case 'U' : flagdrop = 1 ; break ;
        case 'd' : if (!uint0_scan(l.arg, &notif)) dieusage() ; break ;
        case 'f' : conffile = l.arg ; break ;
        default : strerr_dieusage(10, USAGE) ;
      }
    }
    argc -= l.ind ; argv += l.ind ;
    if (flagdrop)
    {
      char const *x = getenv("UID") ;
      if (!x) strerr_dienotset(100, "UID") ;
      if (!uid0_scan(x, &uid)) strerr_dieinvalid(100, "UID") ;
      x = getenv("GID") ;
      if (!x) strerr_dienotset(100, "GID") ;
      if (!uid0_scan(x, &gid)) strerr_dieinvalid(100, "GID") ;
    }
  }

  if (notif)
  {
    if (notif < 3) strerr_dief1x(100, "notification fd cannot be 0, 1 or 2") ;
    if (fcntl(notif, F_GETFD) == -1) strerr_diefu1sys(111, "check notification fd") ;
  }

  close(0) ;
  close(1) ;

  if (!cdb_init(&g->confdb, conffile)) strerr_diefu2sys(111, "open ", conffile) ;
  conf_init(conffile, &n4, &n6, &ip4, &ip6, &maxtcp, &maxqueries) ;

  spfd = selfpipe_init() ;
  if (spfd == -1) strerr_diefu1sys(111, "create selfpipe") ;
  if (!sig_altignore(SIGPIPE)) strerr_diefu1sys(111, "ignore SIGPIPE") ;
  {
    sigset_t set ;
    sigemptyset(&set) ;
    sigaddset(&set, SIGHUP) ;
    sigaddset(&set, SIGTERM) ;
    sigaddset(&set, SIGQUIT) ;
    sigaddset(&set, SIGALRM) ;
    if (!selfpipe_trapset(&set)) strerr_diefu1sys(111, "trap signals") ;
  }

  {
    udpqueue udpq4[n4 ? n4 : 1] ;
    udpqueue udpq6[n6 ? n6 : 1] ;
    int tcp4fd[n4 ? n4 : 1] ;
    int tcp6fd[n6 ? n6 : 1] ;
    uint16_t tcp4xindex[n4 ? n4 : 1] ;
    uint16_t tcp6xindex[n4 ? n4 : 1] ;
    tcpconnection tcpconnection_storage[maxtcp + 1] ;
    uint32_t tcpconnection_freelist[maxtcp + 1] ;
    query query_storage[maxqueries + 1] ;
    uint32_t query_freelist[maxqueries + 1] ;

    memset(udpq4, 0, n4 * sizeof(udpqueue)) ;
    memset(udpq6, 0, n6 * sizeof(udpqueue)) ;
    memset(tcpconnection_storage, 0, (maxtcp + 1) * sizeof(tcpconnection)) ;
    memset(query_storage, 0, (maxqueries + 1) * sizeof(query)) ;
    GENSET_init(&g->tcpconnections, tcpconnection, tcpconnection_storage, tcpconnection_freelist, maxtcp + 1) ;
    g->tcpsentinel = genset_new(&g->tcpconnections) ;
    GENSET_init(&g->queries, query, query_storage, query_freelist, maxqueries + 1) ;
    g->qsentinel = genset_new(&g->queries) ;
    {
      tcpconnection *p = TCPCONNECTION(g->tcpsentinel) ;
      query *q = QUERY(g->qsentinel) ;
      p->prev = p->next = g->tcpsentinel ;
      q->prev = q->next = g->qsentinel ;
    }

    for (uint16_t i = 0 ; i < n4 ; i++)
    {
      udpq4[i].fd = socket_udp4_nbcoe() ;
      if (udpq4[i].fd == -1) strerr_diefu1sys(111, "create udp4 socket") ;
      if (socket_bind4_reuse(udpq4[i].fd, ip4 + (i << 2), 53) == -1)
      {
        char fmt[IP4_FMT] ;
        fmt[ip4_fmt(fmt, ip4 + (i << 2))] = 0 ;
        strerr_diefu3sys(111, "bind to ip ", fmt, " UDP port 53") ;
      }
      tcp4fd[i] = socket_tcp4_nbcoe() ;
      if (tcp4fd[i] == -1) strerr_diefu1sys(111, "create tcp4 socket") ;
      if (socket_bind4_reuse(tcp4fd[i], ip4 + (i << 2), 53) == -1)
      {
        char fmt[IP4_FMT] ;
        fmt[ip4_fmt(fmt, ip4 + (i << 2))] = 0 ;
        strerr_diefu3sys(111, "bind to ip ", fmt, " TCP port 53") ;
      }
    }
#ifdef SKALIBS_IPV6_ENABLED
    for (uint16_t i = 0 ; i < n6 ; i++)
    {
      udpq6[i].fd = socket_udp6_nbcoe() ;
      if (udpq6[i].fd == -1) strerr_diefu1sys(111, "create udp6 socket") ;
      if (socket_bind6_reuse(udpq6[i].fd, ip6 + (i << 4), 53) == -1)
      {
        char fmt[IP6_FMT] ;
        fmt[ip6_fmt(fmt, ip6 + (i << 4))] = 0 ;
        strerr_diefu3sys(111, "bind to ip ", fmt, " UDP port 53") ;
      }
      tcp6fd[i] = socket_tcp6_nbcoe() ;
      if (tcp6fd[i] == -1) strerr_diefu1sys(111, "create tcp6 socket") ;
      if (socket_bind4_reuse(tcp6fd[i], ip6 + (i << 4), 53) == -1)
      {
        char fmt[IP6_FMT] ;
        fmt[ip6_fmt(fmt, ip6 + (i << 4))] = 0 ;
        strerr_diefu3sys(111, "bind to ip ", fmt, " TCP port 53") ;
      }
    }
#endif

    if (gid && setgid(gid) == -1) strerr_diefu1sys(111, "setgid") ;
    if (uid && setuid(uid) == -1) strerr_diefu1sys(111, "setuid") ;

    cache_load() ;
    if (!tain_now_set_stopwatch_g()) strerr_diefu1sys(111, "initialize clock") ;

    if (notif)
    {
      write(notif, "\n", 1) ;
      close(notif) ;
    }


   /* main loop */

    while (cont)   /* quick exit condition */
    {
      tain deadline = TAIN_INFINITE ;
      int r = 0 ;
      uint32_t j = 1 ;
      iopause_fd x[1 + (n4 + n6) * 2 + ntcp + nq] ;


     /* preparation */

      x[0].fd = spfd ;
      x[0].events = IOPAUSE_READ ;
      if (cont == 1 && tain_less(&lameduckt, &deadline)) deadline = lameduckt ;

      for (uint16_t i = 0 ; i < n4 ; i++)
      {
        x[j].fd = udpq4[i].fd ;
        x[j].events = nq < maxqueries && cont >= 2 ? IOPAUSE_READ : 0 ;
        if (genalloc_len(udp4msg, &udpq4[i].messages))
        {
          x[j].events |= IOPAUSE_WRITE ;
          if (tain_less(&udpq4[i].deadline, &deadline)) deadline = udpq4[i].deadline ;
          r = 1 ;
        }
        if (x[j].events) udpq4[i].xindex = j++ ; else udpq4[i].xindex = UINT16_MAX ;

        if (ntcp < maxtcp && cont >= 2)
        {
          x[j].fd = tcp4fd[i] ;
          x[j].events = IOPAUSE_READ ;
          tcp4xindex[i] = j++ ;
        }
        else tcp4xindex[i] = UINT16_MAX ;
      }

#ifdef SKALIBS_IPV6_ENABLED
      for (uint16_t i = 0 ; i < n6 ; i++)
      {
        x[j].fd = udpq6[i].fd ;
        x[j].events = nq < maxqueries && cont >= 2 ? IOPAUSE_READ : 0 ;
        if (genalloc_len(udp6msg, &udpq6[i].messages))
        {
          x[j].events |= IOPAUSE_WRITE ;
          if (tain_less(&udpq6[i].deadline, &deadline)) deadline = udpq6[i].deadline ;
          r = 1 ;
        }
        if (x[j].events) udpq6[i].xindex = j++ ; else udpq6[i].xindex = UINT16_MAX ;

        if (ntcp < maxtcp && cont >= 2)
        {
          x[j].fd = tcp6fd[i] ;
          x[j].events = IOPAUSE_READ ;
          tcp6xindex[i] = j++ ;
        }
        else tcp6xindex[i] = UINT16_MAX ;
      }
#endif

      for (uint16_t i = tcpstart ; i != g->tcpsentinel ; i = TCPCONNECTION(i)->next)
      {
        tcpconnection *p = TCPCONNECTION(i) ;
        x[j].fd = bufalloc_fd(&p->out) ;
        if (nq < maxqueries && cont >= 2)
        {
          x[j].events = IOPAUSE_READ ;
          if (tain_less(&p->rdeadline, &deadline)) deadline = p->rdeadline ;
        }
        else x[j].events = 0 ;
        if (bufalloc_len(&p->out))
        {
          x[j].events |= IOPAUSE_WRITE ;
          if (tain_less(&p->wdeadline, &deadline)) deadline = p->wdeadline ;
          r = 1 ;
        }
        if (x[j].events) p->xindex = j++ ; else p->xindex = UINT16_MAX ;
      }

      for (uint16_t i = qstart ; i != g->qsentinel ; i = QUERY(i)->next)
      {
        query *p = QUERY(i) ;
        x[j].fd = p->dt.fd ;
        s6dns_engine_nextdeadline(&p->dt, &deadline) ;
        x[j].events = (s6dns_engine_isreadable(&p->dt) ? IOPAUSE_READ : 0) | (s6dns_engine_iswritable(&p->dt) ? IOPAUSE_WRITE : 0) ;
        if (x[j].events) p->xindex = j++ ; else p->xindex = UINT16_MAX ;
      }


     /* normal exit condition */

      if (cont < 2 && !r && !nq) break ;


     /* poll() */

      r = iopause_g(x, j, &deadline) ;
      if (r == -1) strerr_diefu1sys(111, "iopause") ;


     /* timeout */

      if (!r)
      {
        if (cont == 1 && !tain_future(&lameduckt)) break ;  /* too lame */
        for (uint16_t i = qstart ; i != g->qsentinel ; i = QUERY(i)->next)
          if (s6dns_engine_timeout_g(&QUERY(i)->dt)) i = query_fail(i) ;
        for (uint16_t i = tcpstart ; i != g->tcpsentinel ; i = TCPCONNECTION(i)->next)
        {
          tcpconnection *p = TCPCONNECTION(i) ;
          if (!tain_future(&p->rdeadline) || !tain_future(&p->wdeadline))
          {
            log_tcptimeout(i) ;
            i = tcpconnection_delete(p) ;
          }
        }
        for (uint16_t i = 0 ; i < n4 ; i++)
          if (!tain_future(&udpq4[i].deadline)) udpqueue_drop(udpq4 + i) ;
        for (uint16_t i = 0 ; i < n6 ; i++)
          if (!tain_future(&udpq6[i].deadline)) udpqueue_drop(udpq6 + i) ;
      }


     /* event */

      else 
      {
        for (uint16_t i = 0 ; i < j ; i++) if (x[i].revents & IOPAUSE_EXCEPT) x[i].revents |= x[i].events ;

        if (x[0].revents & IOPAUSE_READ) { handle_signals() ; continue ; }

        for (uint16_t i = 0 ; i < n4 ; i++) if (udpq4[i].xindex < UINT16_MAX)
        {
          if (x[udpq4[i].xindex].revents & IOPAUSE_WRITE)
          {
            if (udpqueue_flush4(udpq4 + i) == -1)
            {
              char fmt[IP4_FMT] ;
              fmt[ip4_fmt(fmt, ip4 + (i << 2))] = 0 ;
              strerr_diefu2sys(111, "write to UDP socket bound to ", fmt) ;
            }
          }
        }

#ifdef SKALIBS_IPV6_ENABLED
        for (uint16_t i = 0 ; i < n6 ; i++) if (udpq6[i].xindex < UINT16_MAX)
        {
          if (x[udpq6[i].xindex].revents & IOPAUSE_WRITE)
          {
            if (udpqueue_flush6(udpq6 + i) == -1)
            {
              char fmt[IP6_FMT] ;
              fmt[ip6_fmt(fmt, ip6 + (i << 4))] = 0 ;
              strerr_diefu2sys(111, "write to socket bound to ", fmt) ;
            }
          }
        }
#endif

        for (uint16_t i = tcpstart ; i != g->tcpsentinel ; i = TCPCONNECTION(i)->next)
        {
          tcpconnection *p = TCPCONNECTION(i) ;
          if (p->xindex < UINT16_MAX && x[p->xindex].revents & IOPAUSE_WRITE)
            if (tcpconnection_flush(p) == -1) i = tcpconnection_delete(p) ;
        }

        for (uint16_t i = qstart ; i != g->qsentinel ; i = QUERY(i)->next)
        {
          if (QUERY(i)->xindex == UINT16_MAX) continue ;
          r = s6dns_engine_event_g(&QUERY(i)->dt) ;
          if (r < 0) i = query_fail(i) ;
          else if (r > 0) i = query_succeed(i) ;
        }

        for (uint16_t i = 0 ; i < n4 ; i++)
        {
          if (udpq4[i].xindex < UINT16_MAX && x[udpq4[i].xindex].revents & IOPAUSE_READ)
          {
            uint16_t n = MAXSAME ;
            char buf[513] ;
            char ip[4] ;
            uint16_t port ;
            while (n-- && nq < maxqueries)
            {
              ssize_t len = sanitize_read(socket_recv4(udpq4[i].fd, buf, 512, ip, &port)) ;
              if (len == -1)
              {
                char fmt[IP4_FMT] ;
                fmt[ip4_fmt(fmt, ip4 + (i << 2))] = 0 ;
                strerr_diefu2sys(111, "read from UDP socket bound to ", fmt) ;
              }
              if (!len) break ;
              if (len < 12 || len > 512) continue ;
              if (!clientaccess_ip4(ip)) continue ;
              if (!dns_newquery(0, i, ip, port, buf, len))
              {
                if (g->verbosity)
                {
                  char fmtip[IP4_FMT] ;
                  char fmtport[UINT16_FMT] ;
                  fmtip[ip4_fmt(fmtip, ip)] = 0 ;
                  fmtport[uint16_fmt(fmtport, port)] = 0 ;
                  strerr_warnwu4sys("process new UDP query from ip ", fmtip, " port ", fmtport) ;
                }
              }
            }
          }
        }

#ifdef SKALIBS_IPV6_ENABLED
        for (uint16_t i = 0 ; i < n6 ; i++)
        {
          if (udpq6[i].xindex < UINT16_MAX && x[udpq6[i].xindex].revents & IOPAUSE_READ)
          {
            uint16_t n = MAXSAME ;
            char buf[513] ;
            char ip[16] ;
            uint16_t port ;
            while (n-- && nq < maxqueries)
            {
              ssize_t len = sanitize_read(socket_recv6(udpq6[i].fd, buf, 512, ip, &port)) ;
              if (len == -1)
              {
                char fmt[IP6_FMT] ;
                fmt[ip6_fmt(fmt, ip6 + (i << 4))] = 0 ;
                strerr_diefu2sys(111, "read from UDP socket bound to ", fmt) ;
              }
              if (!len) break ;
              if (len < 12 || len > 512) continue ;
              if (!clientaccess_ip6(ip)) continue ;
              if (!dns_newquery(1, i, ip, port, buf, len))
              {
                if (g->verbosity)
                {
                  char fmtip[IP4_FMT] ;
                  char fmtport[UINT16_FMT] ;
                  fmtip[ip4_fmt(fmtip, ip)] = 0 ;
                  fmtport[uint16_fmt(fmtport, port)] = 0 ;
                  strerr_warnwu4sys("process new UDP query from ip ", fmtip, " port ", fmtport) ;
                }
              }
            }
          }
        }
#endif

        for (uint16_t i = tcpstart ; i != g->tcpsentinel ; i = TCPCONNECTION(i)->next)
        {
          tcpconnection *p = TCPCONNECTION(i) ;
          if (p->xindex < UINT16_MAX && x[p->xindex].revents & IOPAUSE_READ)
          {
            uint16_t n = MAXSAME ;
            while (n-- && nq < maxqueries)
            {
              int l = sanitize_read(mininetstring_read(bufalloc_fd(&p->out), &p->in, &p->instate)) ;
              if (l == -1) { i = tcpconnection_delete(p) ; break ; }
              if (!l) break ;
              if (p->in.len < 12 || p->in.len > 65536) { i = tcpconnection_delete(p) ; break ; }
              if (!dns_newquery(2, i, 0, 0, p->in.s, p->in.len))
              {
                if (g->verbosity)
                {
                  char fmt[UINT16_FMT] ;
                  fmt[uint16_fmt(fmt, i)] = 0 ;
                  strerr_warnwu2sys("process TCP query on connection ", fmt) ;
                }
              }
              p->in.len = 0 ;
            }
          }
        }

        for (uint16_t i = 0 ; i < n4 ; i++) if (tcp4xindex[i] < UINT16_MAX)
        {
          if (x[tcp4xindex[i]].revents & IOPAUSE_READ)
          {
            uint16_t n = MAXSAME ;
            while (n-- && ntcp < maxtcp)
            {
              char ip[4] ;
              uint16_t port ;
              int fd = socket_accept4_nbcoe(tcp4fd[i], ip, &port) ;
              if (fd == -1)
              {
                if (error_isagain(errno)) break ;
                strerr_diefu1sys(111, "create new TCP connection") ;
              }
              if (!clientaccess_ip4(ip)) { close(fd) ; continue ; }
              tcpconnection_new(fd) ;
              log_newtcp4(ip, port) ;
            }
          }
        }

#ifdef SKALIBS_IPV6_ENABLED
        for (uint16_t i = 0 ; i < n6 ; i++) if (tcp6xindex[i] < UINT16_MAX)
        {
          if (x[tcp6xindex[i]].revents & IOPAUSE_READ)
          {
            uint16_t n = MAXSAME ;
            while (n-- && ntcp < maxtcp)
            {
              char ip[16] ;
              uint16_t port ;
              int fd = socket_accept6_nbcoe(tcp6fd[i], ip, &port) ;
              if (fd == -1)
              {
                if (error_isagain(errno)) break ;
                strerr_diefu1sys(111, "create new TCP connection") ;
              }
              if (!clientaccess_ip6(ip)) { close(fd) ; continue ; }
              tcpconnection_new(fd) ;
              log_newtcp6(ip, port) ;
            }
          }
        }
#endif

      }
    }
  }

  if (flagwantfinaldump) cache_dump() ;
//  shibari_log_exit(g->verbosity, 0) ;
  return 0 ;
}
