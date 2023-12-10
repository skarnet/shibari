/* ISC license. */

#include <stdint.h>

#include <shibari/util.h>

char const *shibari_util_rcode_str (uint16_t rcode)
{
  static char const *const rcode_table[24] =
  {
    "noerror",
    "formerr",
    "servfail",
    "nxdomain",
    "notimp",
    "refused",
    "yxdomain",
    "yxrrset",
    "nxrrset",
    "notauth",
    "notzone",
    "dsotypeni",
    "unassigned",
    "unassigned",
    "unassigned",
    "unassigned",
    "badsig",
    "badkey",
    "badtime",
    "badmode",
    "badname",
    "badalg",
    "badtrunc",
    "badcookie"
  } ;
  if (rcode < 24) return rcode_table[rcode] ;
  if (rcode < 3841) return "unassigned" ;
  if (rcode < 4096) return "private" ;
  if (rcode < 65535) return "unassigned" ;
  return "reserved" ;
}
