/* ISC license. */

#include <skalibs/fmtscan.h>
#include <skalibs/strerr.h>
#include <skalibs/ip46.h>

#include "shibari-cache-internal.h"



void log_udp4bad (char const *ip, uint16_t port)
{
  if (g->verbosity >= 3)
  {
  }
}

void log_newtcp4 (char const *ip, uint16_t port)
{
  if (g->verbosity >= 3)
  {
  }
}

void log_tcpbad (uint16_t i)
{
  if (g->verbosity >= 3)
  {
  }
}

void log_tcptimeout (uint16_t i)
{
  if (g->verbosity >= 3)
  {
  }
}

#ifdef SKALIBS_IPV6_ENABLED

void log_udp6bad (char const *ip, uint16_t port)
{
  if (g->verbosity >= 3)
  {
  }
}

void log_newtcp6 (char const *ip, uint16_t port)
{
  if (g->verbosity >= 3)
  {
  }
}

#endif
