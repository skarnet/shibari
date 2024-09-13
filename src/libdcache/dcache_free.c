/* ISC license. */

#include <skalibs/gensetdyn.h>
#include <skalibs/avltree.h>

#include <shibari/dcache.h>
#include "dcache-internal.h"

static void dnode_free (void *p)
{
  dcache_node *node = p ;
  dcache_node_free(node) ;
}

void dcache_free (dcache *z)
{
  static dcache const dcache_zero = DCACHE_ZERO ;
  avltree_free(&z->by_expire) ;
  avltree_free(&z->by_entry) ;
  avltree_free(&z->by_key) ;
  gensetdyn_deepfree(&z->storage, &dnode_free) ;
  *z = dcache_zero ;
}
