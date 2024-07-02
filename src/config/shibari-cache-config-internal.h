/* ISC license. */

#ifndef SHIBARI_CACHE_CONFIG_INTERNAL_H
#define SHIBARI_CACHE_CONFIG_INTERNAL_H

#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include <skalibs/buffer.h>
#include <skalibs/strerr.h>
#include <skalibs/stralloc.h>
#include <skalibs/genalloc.h>
#include <skalibs/cdbmake.h>
#include <skalibs/avltree.h>

#define dienomem() strerr_diefu1sys(111, "stralloc_catb")

typedef struct node_s node, *node_ref ;
struct node_s
{
  uint32_t key ;
  uint32_t keylen ;
  uint32_t data ;
  uint32_t datalen ;
  uint32_t filepos ;
  uint32_t line ;
} ;
#define NODE_ZERO { .key = 0, .keylen = 0, .data = 0, .datalen = 0 }

typedef struct repo_s repo, *repo_ref ;
struct repo_s
{
  genalloc ga ;
  avltree tree ;
  stralloc *storage ;
} ;
#define REPO_ZERO { .ga = GENALLOC_ZERO, .tree = AVLTREE_ZERO, .storage = 0 }

struct global_s
{
  stralloc storage ;
} ;
#define GLOBAL_ZERO { .storage = STRALLOC_ZERO }

extern struct global_s g ;


 /* util */

extern int keycmp (void const *, void const *) ;  /* for any struct starting with a string key */
#define BSEARCH(type, key, array) bsearch(key, (array), sizeof(array)/sizeof(type), sizeof(type), &keycmp)


 /* node */

extern void node_start (stralloc *, node *, char const *, size_t, uint32_t) ;
extern void node_add (stralloc *, node *, char const *, size_t) ;


 /* repo */

extern void *node_dtok (uint32_t, void *) ;
extern int node_cmp (void const *, void const *, void *) ;
extern node const *repo_search (repo const *, char const *) ;
extern void repo_add (repo *, node const *) ;
extern void repo_update (repo *, node const *) ;


 /* conftree */

extern void confnode_start (node *, char const *, size_t, uint32_t) ;
extern void confnode_add (node *, char const *, size_t) ;

extern node const *conftree_search (char const *) ;
extern void conftree_add (node const *) ;
extern void conftree_update (node const *) ;

extern int conftree_write (cdbmaker *) ;


 /* lexparse */

extern void conf_lexparse (buffer *, char const *) ;


 /* defaults */

extern void conf_defaults (void) ;

#endif
