/* ISC license. */

#include <shibari/constants.h>
#include <shibari/tdb.h>

int shibari_tdb_extract_domain (shibari_tdb_entry const *entry, cdb_data *domain)
{
  switch (entry->type)
  {
    case SHIBARI_T_CNAME :
    case SHIBARI_T_NS :
      *domain = entry->data ; break ;
    case SHIBARI_T_MX : domain->s = entry->data.s + 2 ; domain->len = entry->data.len - 2 ; break ;
    default : return 0 ;
  }
  return 1 ;
}
