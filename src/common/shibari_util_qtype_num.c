/* ISC license. */

#include <stdint.h>
#include <strings.h>
#include <stdlib.h>

#include <shibari/util.h>

struct map_s
{
  char const *s ;
  uint16_t num ;
} ;

static int map_cmp (void const *a, void const *b)
{
  return strcasecmp((char const *)a, ((struct map_s const *)b)->s) ;
}

#define BSEARCH(key, array) bsearch(key, (array), sizeof(array)/sizeof(struct map_s), sizeof(struct map_s), &map_cmp)

static struct map_s const qtype_table[] =
{
  { "*", 255 },
  { "A", 1 },
  { "A6", 38 },
  { "AAAA", 28 },
  { "AFSDB", 18 },
  { "AMTRELAY", 260 },
  { "ANY", 255 },
  { "APL", 42 },
  { "ATMA", 34 },
  { "AVC", 258 },
  { "AXFR", 252 },
  { "CAA", 257 },
  { "CDNSKEY", 60 },
  { "CDS", 59 },
  { "CERT", 37 },
  { "CNAME", 5 },
  { "CSYNC", 62 },
  { "DHCID", 49 },
  { "DLV", 32769 },
  { "DNAME", 39 },
  { "DNSKEY", 48 },
  { "DOA", 259 },
  { "DS", 43 },
  { "EID", 31 },
  { "EUI48", 108 },
  { "EUI64", 109 },
  { "GID", 102 },
  { "GPOS", 27 },
  { "HINFO", 13 },
  { "HIP", 55 },
  { "HTTPS", 65 },
  { "IPSECKEY", 45 },
  { "ISDN", 20 },
  { "IXFR", 251 },
  { "KEY", 25 },
  { "KX", 36 },
  { "L32", 105 },
  { "L64", 106 },
  { "LOC", 29 },
  { "LP", 107 },
  { "MAILA", 254 },
  { "MAILB", 253 },
  { "MB", 7 },
  { "MD", 3 },
  { "MF", 4 },
  { "MG", 8 },
  { "MINFO", 14 },
  { "MR", 9 },
  { "MX", 15 },
  { "NAPTR", 35 },
  { "NID", 104 },
  { "NIMLOC", 32 },
  { "NINFO", 56 },
  { "NS", 2 },
  { "NSAP", 22 },
  { "NSAP-PTR", 23 },
  { "NSEC", 47 },
  { "NSEC3", 50 },
  { "NSEC3PARAM", 51 },
  { "NULL", 10 },
  { "NXT", 30 },
  { "OPENPGPKEY", 61 },
  { "OPT", 41 },
  { "PTR", 12 },
  { "PX", 26 },
  { "RESINFO", 261 },
  { "RKEY", 57 },
  { "RP", 17 },
  { "RRSIG", 46 },
  { "RT", 21 },
  { "SIG", 24 },
  { "SINK", 40 },
  { "SMIMEA", 53 },
  { "SOA", 6 },
  { "SPF", 99 },
  { "SRV", 33 },
  { "SSHFP", 44 },
  { "SVCB", 64 },
  { "TA", 32768 },
  { "TALINK", 58 },
  { "TKEY", 249 },
  { "TLSA", 52 },
  { "TSIG", 250 },
  { "TXT", 16 },
  { "UID", 101 },
  { "UINFO", 100 },
  { "UNSPEC", 103 },
  { "URI", 256 },
  { "WKS", 11 },
  { "X25", 19 },
  { "ZONEMD", 63 }
} ;

uint16_t shibari_util_qtype_num (char const *s)
{
  struct map_s const *p = BSEARCH(s, qtype_table) ;
  return p ? p->num : 0 ;
}
