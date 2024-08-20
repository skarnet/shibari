/* ISC license. */

#ifndef DCACHE_INTERNAL_H
#define DCACHE_INTERNAL_H

#include <stdint.h>

#include <skalibs/tai.h>
#include <skalibs/avlnode.h>
#include <skalibs/gensetdyn.h>

#include <shibari/dcache.h>

#define DNODE(z, i) GENSETDYN_P(dcache_node, &(z)->storage, i)
#define DCACHE_NODE_OVERHEAD (32 + sizeof(dcache_node) + 3 * sizeof(avlnode))

extern void dcache_delete (dcache *, uint32_t) ;

#endif
