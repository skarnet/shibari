/* ISC license. */

#ifndef SHIBARI_TDB_H
#define SHIBARI_TDB_H

#include <stdint.h>

#include <skalibs/cdb.h>
#include <skalibs/tai.h>

#include <s6-dns/s6dns-message.h>

typedef struct shibari_tdb_entry_s shibari_tdb_entry, *shibari_tdb_entry_ref ;
struct shibari_tdb_entry_s
{
  uint16_t type ;
  uint16_t len ;
  uint32_t ttl ;
  uint32_t flags ;
  cdb_data key ;
  cdb_data data ;
} ;

extern int shibari_tdb_entry_parse (shibari_tdb_entry *, char const *, uint16_t, uint16_t, unsigned int, char const *, tain const *) ;
extern int shibari_tdb_read_entry (cdb const *, cdb_find_state *, shibari_tdb_entry *, char const *, uint16_t, uint16_t, unsigned int, char const *, tain const *, uint32_t *) ;
extern int shibari_tdb_extract_domain (shibari_tdb_entry const *, cdb_data *) ;
extern int shibari_tdb_find_authority (cdb const *, char const *, uint16_t, char const *, tain const *, int *) ;

#endif
