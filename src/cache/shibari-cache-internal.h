/* ISC license. */

#ifndef SHIBARI_CACHE_INTERNAL_H
#define SHIBARI_CACHE_INTERNAL_H

#include <stdint.h>

#include <skalibs/cdb.h>
#include <skalibs/stralloc.h>
#include <skalibs/genalloc.h>
#include <skalibs/bufalloc.h>
#include <skalibs/genset.h>
#include <skalibs/ip46.h>

#include <s6-dns/s6dns-engine.h>

#define MAXXED 1000

 /* cache */

extern dcache_t cache ;


 /* conf */

extern int conf_getb (cdb const *, char const *, size_t, cdb_data *) ;
extern int conf_get (cdb const *, char const *, cdb_data *) ;
extern int conf_get_uint32 (cdb const *, char const *, uint32_t *) ;


 /* tcpconnection */

typedef struct tcpconnection_s tcpconnection, *tcpconnection_ref ;
struct tcpconnection_s
{
  bufalloc out ;
  stralloc in ;
  uint32_t instate ;
} ;
#define TCPCONNECTION_ZERO { .out = BUFALLOC_ZERO, .in = STRALLOC_ZERO, .instate = 0 }

extern genset *tcpconn ;  /* tcpconnection */
#define ntcp (genset_n(tcpconn))


 /* udpqueue */

typedef struct udp4msg_s udp4msg, *udp4msg_ref ;
struct udp4msg_s
{
  char ip[4] ;
  uint16_t port ;
  uint16_t len ;
} ;
#define UDP4MSG_ZERO { .ip = { 0 }, .port = 0, .len = 0 }

typedef struct udp6msg_s udp6msg, *udp6msg_ref ;
struct udp4msg_s
{
  char ip[16] ;
  uint16_t port ;
  uint16_t len ;
} ;
#define UDP6MSG_ZERO { .ip = { 0 }, .port = 0, .len = 0 }

typedef struct udpqueue_s udpqueue, *udpqueue_ref ;
struct udpqueue_s
{
  int fd ;
  stralloc storage ;
  genalloc messages ; /* udp[46]msg */
} ;
#define UDPQUEUE_ZERO { .fd = -1, .storage = STRALLOC_ZERO, .messages = GENALLOC_ZERO }

extern int udpqueue_add4 (udpqueue *, char const *, uint16_t) ;
extern int udpqueue_flush4 (udpqueue *) ;

#ifdef SKALIBS_IPV6_ENABLED
extern int udpqueue_add6 (udpqueue *, char const *, uint16_t) ;
extern int udpqueue_flush6 (udpqueue *) ;
#endif


 /* main */

typedef struct query_s query, *query_ref ;
struct query_s
{
  s6dns_engine_t dt ;
  size_t origin ;
} ;

extern uint32_t verbosity ;
extern cdb confdb ;
extern size_t n4, n6 ;

#endif
