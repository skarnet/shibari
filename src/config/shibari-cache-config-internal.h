/* ISC license. */

#ifndef SHIBARI_CACHE_CONFIG_INTERNAL_H
#define SHIBARI_CACHE_CONFIG_INTERNAL_H

#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include <skalibs/diuint32.h>
#include <skalibs/buffer.h>
#include <skalibs/strerr.h>
#include <skalibs/stralloc.h>
#include <skalibs/genalloc.h>
#include <skalibs/avltree.h>
#include <skalibs/cdbmake.h>

#define dienomem() strerr_diefu1sys(111, "stralloc_catb")
#define diestorage() strerr_diefu2x(100, "add node to configuration tree", ": too much data")

typedef int memcmp_func (void const *, void const *, size_t) ;
typedef memcmp_func *memcmp_func_ref ;

typedef struct node_s node, *node_ref ;
struct node_s
{
  diuint32 key ;
  uint32_t line ;
  stralloc data ;
} ;
#define NODE_ZERO { .key = DIUINT32_ZERO, .line = 0, .data = STRALLOC_ZERO }

typedef struct repo_s repo, *repo_ref ;
struct repo_s
{
  stralloc storage ;
  genalloc list ; /* node */
  avltree tree ;
} ;
#define REPO_ZERO { .storage = STRALLOC_ZERO, .list = GENALLOC_ZERO, .tree = AVLTREE_ZERO }


 /* repo */

extern void repo_init (repo *) ;
extern node *repo_search (repo *, char const *, uint32_t) ;
#define repo_searchs(rp, key) repo_search(rp, (key), strlen(key))
extern void repo_add_new (repo *, char const *, uint32_t, char const *, size_t, uint32_t, int) ;
#define repo_adds_new(rp, key, data, datalen, line, accu) repo_add_new(rp, key, strlen(key), data, datalen, line, accu)
extern uint32_t repo_add (repo *, char const *, uint32_t, char const *, size_t, uint32_t, int, memcmp_func_ref) ;
#define repo_adds(rp, key, data, datalen, line, accu, f) repo_add(rp, key, strlen(key), data, datalen, line, accu, f)
extern int repo_write (cdbmaker *, repo const *) ;
extern void repo_free (repo *) ;


 /* lexparse */

extern void conf_lexparse (buffer *, char const *) ;


 /* defaults */

extern void conf_defaults (void) ;


 /* util */

extern int keycmp (void const *, void const *) ;  /* for any struct starting with a string key */
#define BSEARCH(type, key, array) bsearch(key, (array), sizeof(array)/sizeof(type), sizeof(type), &keycmp)


 /* main */

extern repo conf ;

#endif
