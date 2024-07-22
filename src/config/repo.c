/* ISC license. */

#include <stdint.h>
#include <string.h>

#include <skalibs/diuint32.h>
#include <skalibs/stralloc.h>
#include <skalibs/genalloc.h>
#include <skalibs/avltree.h>
#include <skalibs/cdbmake.h>

#include "shibari-cache-config-internal.h"

static void *node_dtok (uint32_t d, void *aux)
{
  repo *rp = aux ;
  return &genalloc_s(node, &rp->list)[d].key ;
}

static int node_cmp (void const *a, void const *b, void *aux)
{
  repo *rp = aux ;
  diuint32 const *ka = a ;
  diuint32 const *kb = b ;
  if (ka->right < kb->right) return -1 ;
  if (ka->right > kb->right) return 1 ;
  return memcmp(rp->storage.s + ka->left, rp->storage.s + kb->left, ka->right) ;
}

void repo_init (repo *rp)
{
  avltree_init(&rp->tree, 32, 3, 8, &node_dtok, &node_cmp, rp) ;
}

node *repo_search (repo *rp, char const *key, uint32_t keylen)
{
  diuint32 ukey = { .left = rp->storage.len, .right = keylen } ;
  uint32_t i ;
  if (!stralloc_catb(&rp->storage, key, keylen)) dienomem() ;
  rp->storage.len = ukey.left ;
  return avltree_search(&rp->tree, &ukey, &i) ? genalloc_s(node, &rp->list) + i : 0 ;
}

static int checkunique (memcmp_func_ref f, char const *ar, size_t arlen, char const *ele, size_t elelen)
{
  while (arlen >= elelen)
  {
    if (!(*f)(ar, ele, elelen)) return 0 ;
    ar += elelen ;
    arlen -= elelen ;
  }
  return 1 ;
}

void repo_add_new (repo *rp, char const *key, uint32_t keylen, char const *data, size_t datalen, uint32_t line, int accu)
{
  node *nod ;
  uint32_t n = genalloc_len(node, &rp->list) ;
  if (!genalloc_readyplus(node, &rp->list, 1)) dienomem() ;
  nod = genalloc_s(node, &rp->list) + n ;
  nod->key.left = rp->storage.len ;
  nod->key.right = keylen ;
  if (!stralloc_catb(&rp->storage, key, keylen)) dienomem() ;
  nod->line = line ;
  nod->data = stralloc_zero ;
  if (accu)
  {
    if (!stralloc_catb(&nod->data, data, datalen)) dienomem() ;
  }
  else
  {
    nod->data.a = rp->storage.len ;
    nod->data.len = datalen ;
    if (rp->storage.len + datalen > UINT32_MAX) diestorage() ;
    if (!stralloc_catb(&rp->storage, data, datalen)) dienomem() ;
  }
  genalloc_setlen(node, &rp->list, n + 1) ;
  if (!avltree_insert(&rp->tree, n)) dienomem() ;
}

uint32_t repo_add (repo *rp, char const *key, uint32_t keylen, char const *data, size_t datalen, uint32_t line, int accu, memcmp_func_ref f)
{
  node *nod ;
  if (keylen > UINT32_MAX || datalen > UINT32_MAX) diestorage() ;
  nod = repo_search(rp, key, keylen) ;
  if (nod)
  {
    if (!nod->data.s || !accu) return nod->line ;
    if (f && !checkunique(f, nod->data.s, nod->data.len, data, datalen)) return nod->line ;
    if (nod->data.len + datalen > UINT32_MAX) diestorage() ;
    if (!stralloc_catb(&nod->data, data, datalen)) dienomem() ;
  }
  else repo_add_new(rp, key, keylen, data, datalen, line, accu) ;
  return 0 ;
}

static int node_write (cdbmaker *cm, node *nod, char const *s)
{
  return cdbmake_add(cm, s + nod->key.left, nod->key.right, nod->data.s ? nod->data.s : s + nod->data.a, nod->data.len) ;
}

int repo_write (cdbmaker *cm, repo const *rp)
{
  for (size_t i = 0 ; i < genalloc_len(node, &rp->list) ; i++)
    if (!node_write(cm, genalloc_s(node, &rp->list) + i, rp->storage.s))
      return 0 ;
  return 1 ;
}

#if 0
static void node_free (node *nod)
{
  if (nod->data.s) stralloc_free(&nod->data) ;
}

void repo_free (repo *rp)
{
  avltree_free(&rp->tree) ;
  genalloc_deepfree(node, &rp->list, &node_free) ;
  stralloc_free(&rp->storage) ;
}
#endif
