/* ISC license. */

#ifndef SHIBARI_LOG_H
#define SHIBARI_LOG_H

#include <stdint.h>

#include <skalibs/ip46.h>

#include <s6-dns/s6dns-domain.h>
#include <s6-dns/s6dns-message.h>

extern void shibari_log_start (uint32_t, ip46 const *, uint16_t) ;
extern void shibari_log_exit (uint32_t, int) ;

extern void shibari_log_query (uint32_t, s6dns_domain_t const *, uint16_t) ;
extern void shibari_log_queryplus (uint32_t, s6dns_domain_t const *, uint16_t, ip46 const *, uint16_t) ;
extern void shibari_log_answer (uint32_t, s6dns_message_header_t const *, uint16_t) ;

#endif
