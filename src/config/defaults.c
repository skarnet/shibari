/* ISC license. */

#include <stdint.h>

#include "shibari-cache-config-internal.h"

struct defaults_s
{
  char const *key ;
  char const *value ;
  uint32_t vlen ;
} ;

#define REC(k, v, n) { .key = (k), .value = (v), .vlen = (n) }
#define RECS(k, v) REC(k, (v), sizeof(v))
#define RECU16(k, u) { .key = (k), .value = (char const [2]){ (u) >> 8 & 0xffu, (u) & 0xffu }, .vlen = 2 }
#define RECU32(k, u) { .key = (k), .value = (char const [4]){ (u) >> 24 & 0xffu, (u) >> 16 & 0xffu, (u) >> 8 & 0xffu, (u) & 0xffu }, .vlen = 4 }
#define RECU64(k, u) { .key = (k), .value = (char const [8]){ (u) >> 56 & 0xffu, (u) >> 48 & 0xffu, (u) >> 40 & 0xffu, (u) >> 32 & 0xffu, (u) >> 24 & 0xffu, (u) >> 16 & 0xffu, (u) >> 8 & 0xffu, (u) & 0xffu }, .vlen = 8 }

static struct defaults_s const defaults[] =
{
  RECU16("G:logv", 1),
  RECU64("G:cachesize", 1048576ull),
  RECU16("G:maxtcp", 64),
  RECU16("G:maxqueries", 256),
  RECU32("G:rtimeout", 0),
  RECU32("G:wtimeout", 0),
  REC("G:listen4", "\177\0\0\1", 4),
  REC("G:listen6", "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\1", 16),

  REC("R4:",
   "\0\306\51\0\4"
   "\0\252\367\252\2"
   "\0\300\41\4\14"
   "\0\307\7\133\15"
   "\0\300\313\346\12"
   "\0\300\5\5\361"
   "\0\300\160\44\4"
   "\0\306\141\276\65"
   "\0\300\44\224\21"
   "\0\300\72\200\36"
   "\0\301\0\16\201"
   "\0\307\7\123\52"
   "\0\312\14\33\41"
   , 65),

  REC("R6:",
   "\0\40\1\5\3\272\76\0\0\0\0\0\0\0\2\0\60"
   "\0\50\1\1\270\0\20\0\0\0\0\0\0\0\0\0\13"
   "\0\40\1\5\0\0\2\0\0\0\0\0\0\0\0\0\14"
   "\0\40\1\5\0\0\55\0\0\0\0\0\0\0\0\0\15"
   "\0\40\1\5\0\0\250\0\0\0\0\0\0\0\0\0\16"
   "\0\40\1\5\0\0\57\0\0\0\0\0\0\0\0\0\17"
   "\0\40\1\5\0\0\22\0\0\0\0\0\0\0\0\15\15"
   "\0\40\1\5\0\0\1\0\0\0\0\0\0\0\0\0\123"
   "\0\40\1\7\376\0\0\0\0\0\0\0\0\0\0\0\123"
   "\0\40\1\5\3\14\47\0\0\0\0\0\0\0\2\0\60"
   "\0\40\1\7\375\0\0\0\0\0\0\0\0\0\0\0\1"
   "\0\40\1\5\0\0\237\0\0\0\0\0\0\0\0\0\102"
   "\0\40\1\15\303\0\0\0\0\0\0\0\0\0\0\0\65"
   , 221),
  REC(0, 0, 0)
} ;

void conf_defaults (void)
{
  {
    size_t n = genalloc_len(node, &conf.list) ;
    for (size_t i = 0 ; i < n ; i++)
      if (conf.storage.s[genalloc_s(node, &conf.list)[i].key.left] == 'A') goto cont ;
  }

  {
    node *nod = repo_searchs(&conf, "G:listen4") ;
    if (!nod) nod = repo_searchs(&conf, "G:listen6") ;
    if (!nod)
    {
      repo_add_new(&conf, "A4:\b\177\0\0\1", 8, "", 0, 0, 0) ;
      repo_add_new(&conf, "A6:\200\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\1", 20, "", 0, 0, 0) ;
    }
    else strerr_warnw1x("listen directives without accept directives") ;
  }

 cont:
  for (struct defaults_s const *p = defaults ; p->key ; p++)
    if (!repo_searchs(&conf, p->key))
      repo_adds_new(&conf, p->key, p->value, p->vlen, 0, 0) ;
}
