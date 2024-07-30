/* ISC license. */

#ifndef SHIBARI_CACHE_INTERNAL_H
#define SHIBARI_CACHE_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

#include <skalibs/uint64.h>
#include <skalibs/cdb.h>
#include <skalibs/tai.h>
#include <skalibs/strerr.h>
#include <skalibs/stralloc.h>
#include <skalibs/genalloc.h>
#include <skalibs/bufalloc.h>
#include <skalibs/genset.h>
#include <skalibs/ip46.h>

#include <s6-dns/s6dns-domain.h>
#include <s6-dns/s6dns-engine.h>

#include <shibari/dcache.h>

#define dienomem() strerr_diefu1sys(111, "concatenate data") ;


 /* cache */

extern void cache_init (uint64_t) ;
extern void cache_dump (void) ;
extern void cache_load (void) ;
extern int cache_search (s6dns_domain_t const *, uint16_t, dcache_key_t *) ;


 /* clientaccess */

extern int clientaccess_ip4 (char const *) ;
#ifdef SKALIBS_IPV6_ENABLED
extern int clientaccess_ip6 (char const *) ;
#endif


 /* conf */

extern int conf_getb (char const *, size_t, cdb_data *) ;
extern int conf_get (char const *, cdb_data *) ;
extern int conf_get_uint16 (char const *, uint16_t *) ;
extern int conf_get_uint32 (char const *, uint32_t *) ;
extern int conf_get_uint64 (char const *, uint64_t *) ;
extern char const *conf_get_string (char const *) ;


 /* log */

extern void log_udp4bad (char const *, uint16_t) ;
extern void log_newtcp4 (char const *, uint16_t) ;
extern void log_tcpbad (uint16_t) ;
extern void log_tcptimeout (uint16_t) ;
#ifdef SKALIBS_IPV6_ENABLED
extern void log_udp6bad (char const *, uint16_t) ;
extern void log_newtcp6 (char const *, uint16_t) ;
#endif


 /* query */

typedef struct query_s query, *query_ref ;
struct query_s
{
  s6dns_engine_t dt ;
  stralloc qname ;
  uint16_t prev ;
  uint16_t next ;
  uint16_t xindex ;
  uint16_t i ;
  uint16_t port ;
  uint16_t qtype ;
  uint8_t source ;
  char ip[SKALIBS_IP_SIZE] ;
} ;
#define QUERY_ZERO { .dt = S6DNS_ENGINE_ZERO, .qname = STRALLOC_ZERO, .prev = 0, .next = 0, .xindex = UINT16_MAX, .i = 0, .port = 0, qtype = 0, name = 0, .source = 0, .ip = { 0 } }
#define nq (genset_n(&g->queries) - 1)
#define QUERY(i) genset_p(query, &g->queries, (i))
#define qstart (QUERY(g->qsentinel)->next)

extern uint16_t query_abort (uint16_t) ;
extern uint16_t query_fail (uint16_t) ;
extern uint16_t query_succeed (uint16_t) ;

extern int query_start (uint8_t, uint16_t, char const *, uint16_t, char const *, uint16_t) ;
extern int query_end (uint8_t, uint16_t, char const *, uint16_t, char const *, uint16_t) ;

 /* tcpconnection */

typedef struct tcpconnection_s tcpconnection, *tcpconnection_ref ;
struct tcpconnection_s
{
  bufalloc out ;
  stralloc in ;
  uint32_t instate ;
  tain rdeadline ;
  tain wdeadline ;
  genalloc queries ;  /* uint16_t */
  uint16_t prev ;
  uint16_t next ;
  uint16_t xindex ;
} ;
#define TCPCONNECTION_ZERO { .out = BUFALLOC_ZERO, .in = STRALLOC_ZERO, .instate = 0, .rdeadline = TAIN_INFINITE, .wdeadline = TAIN_INFINITE, .queries = GENALLOC_ZERO, .prev = 0, .next = 0, .xindex = UINT16_MAX }
#define ntcp (genset_n(&g->tcpconnections) - 1)
#define TCPCONNECTION(i) genset_p(tcpconnection, &g->tcpconnections, (i))
#define tcpstart (TCPCONNECTION(g->tcpsentinel)->next)

extern void tcpconnection_removequery (tcpconnection *, uint16_t) ;
extern uint16_t tcpconnection_delete (tcpconnection *) ;
extern int tcpconnection_flush (tcpconnection *) ;
extern void tcpconnection_new (int) ;


 /* udpqueue */

typedef struct udpaux_s udpaux, *udpaux_ref ;
struct udpaux_s
{
  uint16_t port ;
  uint16_t len ;
} ;
#define UDPAUX_ZERO { .port = 0, .len = 0 }

typedef struct udpqueue_s udpqueue, *udpqueue_ref ;
struct udpqueue_s
{
  int fd ;
  stralloc storage ;
  genalloc messages ; /* udpaux */
  tain deadline ;
  uint16_t xindex ;
} ;
#define UDPQUEUE_ZERO { .fd = -1, .storage = STRALLOC_ZERO, .messages = GENALLOC_ZERO, .deadline = TAIN_INFINITE, .xindex = UINT16_MAX }

extern void udpqueue_drop (udpqueue *) ;

extern int udpqueue_add (udpqueue *, uint8_t, char const *, uint16_t, char const *, uint16_t) ;
extern int udpqueue_flush (udpqueue *, uint8_t) ;


 /* main */

typedef struct global_s global, *global_ref ;
struct global_s
{
  cdb confdb ;
  char const *dumpfile ;
  uint16_t verbosity ;
  tain rtto ;
  tain wtto ;
  udpqueue *udpqueues[2] ;
  genset tcpconnections ;  /* tcpconnection */
  genset queries ;  /* query */
  uint16_t tcpsentinel ;
  uint16_t qsentinel ;
} ;
#define GLOBAL_ZERO { \
  .confdb = CDB_ZERO, \
  .dumpfile = 0, \
  .verbosity = 1, \
  .rtto = TAIN_INFINITE, \
  .wtto = TAIN_INFINITE, \
  .udpqueues = { 0, 0 }, \
  .tcpconnections = GENSET_ZERO, \
  .queries = GENSET_ZERO, \
  .tcpsentinel = 0, \
  .qsentinel = 0, \
}

extern global *g ;

#endif
