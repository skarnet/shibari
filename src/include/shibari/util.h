/* ISC license. */

#ifndef SHIBARI_UTIL_H
#define SHIBARI_UTIL_H

#include <stdint.h>

#include <s6-dns/s6dns-domain.h>

extern char const *shibari_util_qtype_str (uint16_t) ;
extern uint16_t shibari_util_qtype_num (char const *) ;
extern char const *shibari_util_rcode_str (uint16_t) ;

extern void shibari_util_canon_domain (s6dns_domain_t *, s6dns_domain_t const *) ;
extern int shibari_util_get_prefixlen (char const *, uint16_t, char const *, uint16_t) ;

#endif
