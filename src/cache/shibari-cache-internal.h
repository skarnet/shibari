/* ISC license. */

#ifndef SHIBARI_CACHE_INTERNAL_H
#define SHIBARI_CACHE_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

#include <skalibs/uint64.h>
#include <skalibs/cdb.h>
#include <skalibs/tai.h>
#include <skalibs/stralloc.h>
#include <skalibs/genalloc.h>
#include <skalibs/bufalloc.h>
#include <skalibs/genset.h>
#include <skalibs/ip46.h>

#include <s6-dns/s6dns-engine.h>


 /* cache */

extern void cache_init (uint64_t) ;
extern void cache_dump (void) ;
extern void cache_load (void) ;


 /* clientaccess */

extern int clientaccess_ip4 (char const *) ;
#if SKALIBS_IPV6_ENABLED
extern int clientaccess_ip6 (char const *) ;
#endif

 /* conf */

extern int conf_getb (cdb const *, char const *, size_t, cdb_data *) ;
extern int conf_get (cdb const *, char const *, cdb_data *) ;
extern int conf_get_uint16 (cdb const *, char const *, uint16_t *) ;
extern int conf_get_uint32 (cdb const *, char const *, uint32_t *) ;
extern int conf_get_uint64 (cdb const *, char const *, uint64_t *) ;
extern char const *conf_get_string (cdb const *, char const *) ;


 /* query */

typedef struct query_s query, *query_ref ;
struct query_s
{
  s6dns_engine_t dt ;
  uint16_t prev ;
  uint16_t next ;
  uint16_t xindex ;
  uint16_t source ;
  uint16_t i ;
  uint16_t port ;
  char ip[SKALIBS_IP_SIZE] ;
} ;
#define QUERY_ZERO { .dt = S6DNS_ENGINE_ZERO, .prev = 0, .next = 0, .xindex = UINT16_MAX, .source = 0, .i = 0, .port = 0, .ip = { 0 } }
#define nq (genset_n(&g->queries) - 1)
#define QUERY(i) genset_p(query, &g->queries, (i))
#define qstart (QUERY(g->qsentinel)->next)

extern void query_fail (query *) ;
extern void query_success (query *) ;
extern void query_new (uint8_t, uint16_t, char const *, uint16_t, char const *, uint16_t) ;


 /* tcpconnection */

typedef struct tcpconnection_s tcpconnection, *tcpconnection_ref ;
struct tcpconnection_s
{
  bufalloc out ;
  stralloc in ;
  uint32_t instate ;
  tain rdeadline ;
  tain wdeadline ;
  uint16_t prev ;
  uint16_t next ;
  uint16_t xindex ;
} ;
#define TCPCONNECTION_ZERO { .out = BUFALLOC_ZERO, .in = STRALLOC_ZERO, .instate = 0, .rdeadline = TAIN_INFINITE, .wdeadline = TAIN_INFINITE, .prev = 0, .next = 0. .xindex = UINT32_MAX }
#define ntcp (genset_n(&g->tcpconnections) - 1)
#define TCPCONNECTION(i) genset_p(tcpconnection, &g->tcpconnections, (i))
#define tcpstart (TCPCONNECTION(g->tcpsentinel)->next)

extern void tcpconnection_drop (tcpconnection *) ;
extern int tcpconnection_new (uint8_t, uint16_t, int, char const *, uint16_t) ;


 /* udpqueue */

typedef struct udp4msg_s udp4msg, *udp4msg_ref ;
struct udp4msg_s
{
  char ip[4] ;
  uint16_t port ;
  uint16_t len ;
} ;
#define UDP4MSG_ZERO { .ip = { 0 }, .port = 0, .len = 0 }

#ifdef SKALIBS_IPV6_ENABLED
typedef struct udp6msg_s udp6msg, *udp6msg_ref ;
struct udp4msg_s
{
  char ip[16] ;
  uint16_t port ;
  uint16_t len ;
} ;
#define UDP6MSG_ZERO { .ip = { 0 }, .port = 0, .len = 0 }
#endif

typedef struct udpqueue_s udpqueue, *udpqueue_ref ;
struct udpqueue_s
{
  int fd ;
  stralloc storage ;
  genalloc messages ; /* udp[46]msg */
  tain deadline ;
  uint16_t xindex ;
} ;
#define UDPQUEUE_ZERO { .fd = -1, .storage = STRALLOC_ZERO, .messages = GENALLOC_ZERO, .deadline = TAIN_INFINITE, .xindex = UINT32_MAX }

extern void udpqueue_drop (udpqueue *) ;

extern int udpqueue_add4 (udpqueue *, char const *, uint16_t) ;
extern int udpqueue_flush4 (udpqueue *) ;

#ifdef SKALIBS_IPV6_ENABLED
extern int udpqueue_add6 (udpqueue *, char const *, uint16_t) ;
extern int udpqueue_flush6 (udpqueue *) ;
#endif


 /* main */

typedef struct global_s global, *global_ref ;
struct global_s
{
  cdb confdb ;
  char const *dumpfile ;
  uint16_t verbosity ;
  tain rtto ;
  tain wtto ;
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
  .tcpconnections = GENSET_ZERO, \
  .queries = GENSET_ZERO, \
  .tcpsentinel = 0, \
  .qsentinel = 0, \
}

extern global *g ;

#endif
