/* ISC license. */

#include <skalibs/stralloc.h>
#include <skalibs/gensetdyn.h>
#include <skalibs/avltree.h>

#include <shibari/dcache.h>

static void dcache_node_free (void *p)
{
  dcache_node *node = p ;
  stralloc_free(&node->sa) ;
}

void dcache_free (dcache *z)
{
  static dcache const dcache_zero = DCACHE_ZERO ;
  avltree_free(&z->by_expire) ;
  avltree_free(&z->by_entry) ;
  avltree_free(&z->by_key) ;
  gensetdyn_deepfree(&z->storage, &dcache_node_free) ;
  *z = dcache_zero ;
}
