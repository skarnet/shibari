/* ISC license. */

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include <skalibs/uint32.h>
#include <skalibs/bitarray.h>
#include <skalibs/buffer.h>
#include <skalibs/strerr.h>
#include <skalibs/stralloc.h>
#include <skalibs/genalloc.h>
#include <skalibs/skamisc.h>

#include <s6-dns/s6dns-domain.h>

#include <shibari/config.h>
#include "shibari-cache-config-internal.h"

#define dietoobig() strerr_diefu1sys(100, "read configuration")

typedef struct mdt_s mdt, *mdt_ref ;
struct mdt_s
{
  size_t filepos ;
  uint32_t line ;
  char linefmt[UINT32_FMT] ;
} ;
#define MDT_ZERO { .filepos = 0, .line = 0, .linefmt = "0" }

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

static void conftree_checkunique (char const *key, mdt const *md)
{
  node const *node = conftree_search(key) ;
  if (node)
  {
    char fmt[UINT32_FMT] ;
    fmt[uint32_fmt(fmt, node->line)] = 0 ;
    strerr_diefn(1, 12, "duplicate ", "key ", key, " in file ", g.storage.s + md->filepos, " line ", md->linefmt, ", previously defined", " in file ", g.storage.s + node->filepos, " line ", fmt) ;
  }
}

static void add_unique (char const *key, char const *value, size_t valuelen, mdt const *md)
{
  node node ;
  conftree_checkunique(key, md) ;
  confnode_start(&node, key, md->filepos, md->line) ;
  confnode_add(&node, value, valuelen) ;
  conftree_add(&node) ;
}

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

static inline void parse_verbosity (char const *s, size_t const *word, size_t n, mdt const *md)
{
  uint32_t v ;
  char pack[4] ;
  if (n != 1)
    strerr_dief8x(1, "too ", n ? "many" : "few", " arguments to directive ", "verbosity", " in file ", g.storage.s + md->filepos, " line ", md->linefmt) ;
  if (!uint320_scan(s + word[0], &v))
    strerr_dief7x(1, " argument to directive ", "verbosity", " must be an integer ", " in file ", g.storage.s + md->filepos, " line ", md->linefmt) ;
  uint32_pack_big(pack, v) ;
  add_unique("G:logv", pack, 4, md) ;
}

static inline void parse_maxtcp (char const *s, size_t const *word, size_t n, mdt const *md)
{
  uint32_t max ;
  char pack[4] ;
  if (n != 1)
    strerr_dief8x(1, "too ", n ? "many" : "few", " arguments to directive ", "maxtcp", " in file ", g.storage.s + md->filepos, " line ", md->linefmt) ;
  if (!uint320_scan(s + word[0], &max))
    strerr_dief7x(1, " argument to directive ", "maxtcp", " must be an integer ", " in file ", g.storage.s + md->filepos, " line ", md->linefmt) ;
  if (max > 4000)
    strerr_dief7x(1, " argument to directive ", "maxtcp", " must be 4000 or less ", " in file ", g.storage.s + md->filepos, " line ", md->linefmt) ;
  uint32_pack_big(pack, max) ;
  add_unique("G:maxtcp", pack, 4, md) ;
}

static inline void parse_listen (char const *s, size_t const *word, size_t n, mdt const *md)
{
  if (!n)
    strerr_dief6x(1, "too few arguments to directive ", "listen", " in file ", g.storage.s + md->filepos, " line ", md->linefmt) ;
  {
    size_t n4 = 0, n6 = 0 ;
    char ip6[n << 4] ;
    char ip4[n << 2] ;
    for (size_t i = 0 ; i < n ; i++)
    {
      if (ip60_scan(s + word[i], ip6 + (n6 << 4))) n6++ ;
      else if (ip40_scan(s + word[i], ip4 + (n4 << 2))) n4++ ;
      else strerr_dief6x(1, "arguments to directive ", "listen", " must be IPs in file ", g.storage.s + md->filepos, " line ", md->linefmt) ;
    }
    add_unique("G:listen4", ip4, n4 << 2, md) ;
    add_unique("G:listen6", ip6, n6 << 4, md) ;
  }
}

static inline void parse_accept (char const *s, size_t const *word, size_t n, mdt const *md)
{
}

static inline void parse_server (char const *s, size_t const *word, size_t n, mdt const *md, int forward)
{
  char const *x = forward ? "forward" : "server" ;
  s6dns_domain_t domain ;
  if (n-- < 2)
    strerr_dief8x(1, "too ", "few", " arguments to directive ", x, " in file ", g.storage.s + md->filepos, " line ", md->linefmt) ;
  if (!s6dns_domain_fromstring(&domain, s + word[0], strlen(s + word[0]))
   || !s6dns_domain_noqualify(&domain))
    strerr_dief7x(1, "first argument to directive ", x, " must be a zone ", " in file ", g.storage.s + md->filepos, " line ", md->linefmt) ;
  word++ ;
  {
    size_t n4 = 0, n6 = 0 ;
    char ip6[n * 17] ;
    char ip4[n * 5] ;
    char key[3 + domain.len] ;
    for (size_t i = 0 ; i < n ; i++)
    {
      if (ip60_scan(s + word[i], ip6 + (n6 * 17) + 1)) ip6[n6++ * 17] = !!forward ;
      else if (ip40_scan(s + word[i], ip4 + (n4 * 5) + 1)) ip4[n4++ * 5] = !!forward ;
      else strerr_dief6x(1, "subsequent arguments to directive ", x, " must be IPs in file ", g.storage.s + md->filepos, " line ", md->linefmt) ;
    }
    memcpy(key, "R4:", 3) ;
    memcpy(key + 3, domain.s + 1, domain.len - 1) ;
    key[2 + domain.len] = 0 ;
    add_unique(key, ip4, n4 * 5, md) ;
    key[1] = '6' ;
    add_unique(key, ip6, n6 * 17, md) ; 
  }
}

static inline void process_line (char const *s, size_t const *word, size_t n, mdt *md)
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
  if (!directive)
    strerr_dief6x(1, "unrecognized word ", word0, " in file ", g.storage.s + md->filepos, " line ", md->linefmt) ;
  switch (directive->value)
  {
    case T_VERBOSITY :
      parse_verbosity(s, word, n, md) ;
      break ;
    case T_MAXTCP :
      parse_maxtcp(s, word, n, md) ;
      break ;
    case T_LISTEN :
      parse_listen(s, word, n, md) ;
      break ;
    case T_ACCEPT :
      parse_accept(s, word, n, md) ;
      break ;
    case T_SERVER :
      parse_server(s, word, n, md, 0) ;
      break ;
    case T_FORWARD :
      parse_server(s, word, n, md, 1) ;
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

static inline char next (buffer *b, mdt const *md)
{
  char c ;
  ssize_t r = buffer_get(b, &c, 1) ;
  if (r == -1) strerr_diefu1sys(111, "read from preprocessor") ;
  if (!r) return 0 ;
  if (!c) strerr_dief5x(1, "null character", " in file ", g.storage.s + md->filepos, " line ", md->linefmt) ;
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
  mdt md = MDT_ZERO ;
  uint8_t state = 0 ;
  if (!stralloc_catb(&g.storage, ifile, strlen(ifile) + 1)) dienomem() ;
  while (state < 0x04)
  {
    char c = next(b, &md) ;
    uint8_t what = table[state][cclass(c)] ;
    state = what & 0x07 ;
    if (what & 0x10) if (!genalloc_catb(size_t, &words, &sa.len, 1)) dienomem() ;
    if (what & 0x20) if (!stralloc_catb(&sa, &c, 1)) dienomem() ; 
    if (what & 0x40) if (!stralloc_0(&sa)) dienomem() ;
    if (what & 0x80)
    {
      process_line(sa.s, genalloc_s(size_t, &words), genalloc_len(size_t, &words), &md) ;
      genalloc_setlen(size_t, &words, 0) ;
      sa.len = 0 ;
      md.line++ ;
      md.linefmt[uint32_fmt(md.linefmt, md.line)] = 0 ;
    }
  }
  genalloc_free(size_t, &words) ;
  stralloc_free(&sa) ;
}
