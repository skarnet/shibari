/* ISC license. */

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include <skalibs/gccattributes.h>
#include <skalibs/uint16.h>
#include <skalibs/uint32.h>
#include <skalibs/fmtscan.h>
#include <skalibs/bitarray.h>
#include <skalibs/buffer.h>
#include <skalibs/strerr.h>
#include <skalibs/stralloc.h>
#include <skalibs/genalloc.h>
#include <skalibs/skamisc.h>

#include <s6-dns/s6dns-domain.h>

#include "shibari-cache-config-internal.h"

struct namevalue_s
{
  char const *name ;
  uint32_t value ;
} ;

enum directivevalue_e
{
  T_VERBOSITY,
  T_MAXTCP,
  T_LISTEN,
  T_ACCEPT,
  T_SERVER,
  T_FORWARD,
} ;

static void dieparse (char const *, uint32_t, char const *, char const *, char const *, uint32_t, uint32_t) gccattr_noreturn ;
static void dieparse (char const *ifile, uint32_t line, char const *directive, char const *what, char const *key, uint32_t keylen, uint32_t prevline)
{
  unsigned int m = 3 ;
  stralloc sa = STRALLOC_ZERO ;
  char const *ar[11] = { "in file ", ifile, " line " } ;
  char fmtl[UINT32_FMT] ;
  char fmtp[UINT32_FMT] ;
  fmtl[uint32_fmt(fmtl, line)] = 0 ;
  ar[m++] = fmtl ;
  if (directive)
  {
    ar[m++] = " directive " ;
    ar[m++] = directive ;
  }
  ar[m++] = ": " ;
  ar[m++] = what ;
  if (key)
  {
    if (!string_quote(&sa, key, keylen) || !stralloc_0(&sa)) dienomem() ;
    ar[m++] = sa.s ;
  }
  if (prevline)
  {
    fmtp[uint32_fmt(fmtp, prevline)] = 0 ;
    ar[m++] = " - see line " ;
    ar[m++] = fmtp ;
  }
  strerr_diev(1, ar, m) ;
}

static void add_unique (char const *ifile, uint32_t line, char const *directive, char const *key, uint32_t keylen, char const *data, size_t datalen)
{
  uint32_t prev = repo_add(&conf, key, keylen, data, datalen, line, 0, 0) ;
  if (prev) dieparse(ifile, line, directive, "duplicate key ", key, keylen, prev) ;
}
#define adds_unique(ifile, line, directive, key, data, datalen) add_unique(ifile, line, directive, key, strlen(key), data, datalen)

static void add_accu (char const *ifile, uint32_t line, char const *directive, char const *key, uint32_t keylen, char const *data, size_t datalen, memcmp_func_ref f)
{
  uint32_t prev = repo_add(&conf, key, keylen, data, datalen, line, 1, f) ;
  if (prev) dieparse(ifile, line, directive, "value already listed for key ", key, keylen, prev) ;
}
#define adds_accu(ifile, line, directive, key, data, datalen, f) add_accu(ifile, line, directive, key, strlen(key), data, datalen, f)

static int ip40_scan (char const *s, char *ip)
{
  size_t len = ip4_scan(s, ip) ;
  return len ? !s[len] : 0 ;
}

static int ip60_scan (char const *s, char *ip)
{
  size_t len = ip6_scan(s, ip) ;
  return len ? !s[len] : 0 ;
}

static int ipcmp (void const *a, void const *b, size_t n)
{
  char const *aa = a ;
  char const * bb = b ;
  return memcmp(aa+1, bb+1, n-1) ;
}


static inline void parse_verbosity (char const *s, size_t const *word, size_t n, char const *ifile, uint32_t line)
{
  uint32_t v ;
  char pack[4] ;
  if (n != 1) dieparse(ifile, line, "verbosity", n ? "too many arguments" : "too few arguments", 0, 0, 0) ;
  if (!uint320_scan(s + word[0], &v)) dieparse(ifile, line, "verbosity", "argument must be an integer", 0, 0, 0) ;
  uint32_pack_big(pack, v) ;
  adds_unique(ifile, line, "verbosity", "G:logv", pack, 4) ;
}

static inline void parse_maxtcp (char const *s, size_t const *word, size_t n, char const *ifile, uint32_t line)
{
  uint32_t max ;
  char pack[4] ;
  if (n != 1) dieparse(ifile, line, "maxtcp", n ? "too many arguments" : "too few arguments", 0, 0, 0) ;
  if (!uint320_scan(s + word[0], &max)) dieparse(ifile, line, "maxtcp", "argument must be an integer", 0, 0, 0) ;
  if (max > 4000) dieparse(ifile, line, "maxtcp", "argument must be 4000 or less", 0, 0, 0) ;
  uint32_pack_big(pack, max) ;
  adds_unique(ifile, line, "maxtcp", "G:maxtcp", pack, 4) ;
}

static inline void parse_listen (char const *s, size_t const *word, size_t n, char const *ifile, uint32_t line)
{
  if (!n) dieparse(ifile, line, "listen", "too few arguments", 0, 0, 0) ;
  for (size_t i = 0 ; i < n ; i++)
  {
    char ip[16] ;
    char key[10] = "G:listen?" ;
    if (ip60_scan(s + word[i], ip)) key[8] = '6' ;
    else if (ip40_scan(s + word[i], ip)) key[8] = '4' ;
    else dieparse(ifile, line, "listen", "arguments must be IP addresses", 0, 0, 0) ;
    adds_accu(ifile, line, "listen", key, ip, key[8] == '6' ? 16 : 4, &memcmp) ;
  }
  adds_accu(ifile, line, "listen", "G:listen4", "", 0, 0) ;
  adds_accu(ifile, line, "listen", "G:listen6", "", 0, 0) ;
}

static inline void parse_accept (char const *s, size_t const *word, size_t n, char const *ifile, uint32_t line)
{
  char key[20] = "A?:" ;
  if (!n) dieparse(ifile, line, "accept", "too few arguments", 0, 0, 0) ;
  for (size_t i = 0 ; i < n ; i++)
  {
    uint16_t mask ;
    size_t len = ip6_scan(s + word[i], key + 4) ;
    if (!len)
    {
       len = ip4_scan(s + word[i], key + 4) ;
       if (!len) dieparse(ifile, line, "accept", "arguments must be ip/netmask", 0, 0, 0) ;
       key[1] = '4' ;
    }
    else key[1] = '6' ;
    if ((s[word[i] + len] != '/' && s[word[i] + len] != '_')
     || !uint160_scan(s + word[i] + len + 1, &mask)
     || mask > (key[1] == 6 ? 128 : 32))
      dieparse(ifile, line, "accept", "arguments must be ip/netmask", 0, 0, 0) ;
    key[3] = (uint8_t)mask ;
    if (key[1] == '6') ip6_netmask(key + 4, mask) ; else ip4_netmask(key + 4, mask) ;
    add_unique(ifile, line, "accept", key, key[1] == '6' ? 20 : 8, "", 0) ;
  }
}

static inline void parse_server (char const *s, size_t const *word, size_t n, char const *ifile, uint32_t line, int forward)
{
  char const *what = forward ? "forward" : "server" ;
  s6dns_domain_t domain ;
  char key[258] = "R?:" ;
  char data[17] ;
  if (n-- < 2) dieparse(ifile, line, what, "too few arguments", 0, 0, 0) ;
  if (!s6dns_domain_fromstring_noqualify_encode(&domain, s + word[0], strlen(s + word[0])))
    dieparse(ifile, line, what, "first argument must be a zone", 0, 0, 0) ;
  word++ ;
  memcpy(key + 3, domain.s, domain.len - 1) ;
  for (size_t i = 0 ; i < n ; i++)
  {
    if (ip60_scan(s + word[i], data + 1)) key[1] = '6' ;
    else if (ip40_scan(s + word[i], data + 1)) key[1] = '4' ;
    else dieparse(ifile, line, what, "second and subsequent arguments must be IP addresses", 0, 0, 0) ;
    data[0] = !!forward ;
    add_accu(ifile, line, what, key, 3 + domain.len, data, key[1] == '6' ? 17 : 5, &ipcmp) ;
  }
  if (domain.len == 1)
  {
    adds_accu(ifile, line, what, "R4:", "", 0, 0) ;
    adds_accu(ifile, line, what, "R6:", "", 0, 0) ;
  }
}


static inline void process_line (char const *s, size_t const *word, size_t n, char const *ifile, uint32_t line)
{
  static struct namevalue_s const directives[] =
  {
    { .name = "accept", .value = T_ACCEPT },
    { .name = "forward", .value = T_FORWARD },
    { .name = "listen", .value = T_LISTEN },
    { .name = "maxtcp", .value = T_MAXTCP },
    { .name = "server", .value = T_SERVER },
    { .name = "verbosity", .value = T_VERBOSITY },
  } ;
  struct namevalue_s const *directive ;
  char const *word0 ;
  if (!n--) return ;
  word0 = s + *word++ ;
  directive = BSEARCH(struct namevalue_s, word0, directives) ;
  if (!directive) dieparse(ifile, line, 0, "unrecognized word: ", word0, strlen(word0), 0) ;
  switch (directive->value)
  {
    case T_VERBOSITY :
      parse_verbosity(s, word, n, ifile, line) ;
      break ;
    case T_MAXTCP :
      parse_maxtcp(s, word, n, ifile, line) ;
      break ;
    case T_LISTEN :
      parse_listen(s, word, n, ifile, line) ;
      break ;
    case T_ACCEPT :
      parse_accept(s, word, n, ifile, line) ;
      break ;
    case T_SERVER :
      parse_server(s, word, n, ifile, line, 0) ;
      break ;
    case T_FORWARD :
      parse_server(s, word, n, ifile, line, 1) ;
      break ;
  }
}

static inline uint8_t cclass (char c)
{
  switch (c)
  {
    case 0 : return 0 ;
    case ' ' :
    case '\t' :
    case '\f' :
    case '\r' : return 1 ;
    case '#' : return 2 ;
    case '\n' : return 3 ;
    default : return 4 ;
  }
}

static inline char next (buffer *b, char const *ifile, uint32_t line)
{
  char c ;
  ssize_t r = buffer_get(b, &c, 1) ;
  if (r == -1) strerr_diefu1sys(111, "read from preprocessor") ;
  if (!r) return 0 ;
  if (!c) dieparse(ifile, line, 0, "null character", 0, 0, 0) ;
  return c ;
}

void conf_lexparse (buffer *b, char const *ifile)
{
  static uint8_t const table[4][5] =  /* see PARSING-config.txt */
  {
    { 0x04, 0x02, 0x01, 0x80, 0x33 },
    { 0x04, 0x01, 0x01, 0x80, 0x01 },
    { 0x84, 0x02, 0x01, 0x80, 0x33 },
    { 0xc4, 0x42, 0x23, 0xc0, 0x23 }
  } ;
  stralloc sa = STRALLOC_ZERO ;
  genalloc words = GENALLOC_ZERO ; /* size_t */
  uint32_t line = 1 ;
  uint8_t state = 0 ;
  while (state < 0x04)
  {
    char c = next(b, ifile, line) ;
    uint8_t what = table[state][cclass(c)] ;
    state = what & 0x07 ;
    if (what & 0x10) if (!genalloc_catb(size_t, &words, &sa.len, 1)) dienomem() ;
    if (what & 0x20) if (!stralloc_catb(&sa, &c, 1)) dienomem() ; 
    if (what & 0x40) if (!stralloc_0(&sa)) dienomem() ;
    if (what & 0x80)
    {
      process_line(sa.s, genalloc_s(size_t, &words), genalloc_len(size_t, &words), ifile, line) ;
      genalloc_setlen(size_t, &words, 0) ;
      sa.len = 0 ;
      line++ ;
    }
  }
  genalloc_free(size_t, &words) ;
  stralloc_free(&sa) ;
}
