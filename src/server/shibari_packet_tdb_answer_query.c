/* ISC license. */

#include <skalibs/cdb.h>

#include <shibari/constants.h>
#include <shibari/tdb.h>
#include <shibari/packet.h>

static unsigned int childzone (shibari_packet *pkt, cdb const *tdb, s6dns_domain_t const *q, char const *loc, tain const *stamp, uint16_t nplen, uint16_t zplen)
{
  cdb_find_state state = CDB_FIND_STATE_ZERO ;
  unsigned int gr ;
  for (;;)
  {
    shibari_tdb_entry ns ;
    int r = shibari_tdb_read_entry(tdb, &state, &ns, q->s + nplen, q->len - nplen, SHIBARI_T_NS, 0, loc, stamp, 0) ;
    if (r == -1) return 2 ;
    if (!r) break ;
    r = shibari_packet_add_rr(pkt, &ns, nplen, 0, 3) ;
    if (!r) { pkt->hdr.tc = 1 ; goto end ; }
  }
  gr = shibari_packet_add_glue(pkt, tdb, q->s + nplen, q->len - nplen, SHIBARI_T_NS, q->s + zplen, q->len - zplen, zplen, 0, loc, stamp) ;
  if (gr > 0) return gr ;
 end:
  shibari_packet_end(pkt) ;
  return 0 ;
}

unsigned int shibari_packet_tdb_answer_query (shibari_packet *pkt, cdb const *tdb, s6dns_message_header_t const *qhdr, s6dns_domain_t const *q, uint16_t qtype, char const *loc, tain const *stamp)
{
  unsigned int rcode = 0 ;
  cdb_find_state state = CDB_FIND_STATE_ZERO ;
  uint32_t flagyxdomain = 0 ;
  int nplen, zplen ;
  uint16_t gluetype = 0 ;
  uint16_t wildpos = 0 ;

  shibari_packet_begin(pkt, qhdr->id, q, qtype) ;
  pkt->hdr.rd = qhdr->rd ;
  zplen = shibari_tdb_find_authority(tdb, q->s, q->len, loc, stamp, &nplen) ;
  switch (zplen)
  {
    case -2 : return 9 ;
    case -1 : return 2 ;
    default : break ;
  }
  if (nplen >= 0 && nplen < zplen)
    return childzone(pkt, tdb, q, loc, stamp, nplen, zplen) ;

  pkt->hdr.aa = 1 ;  /* we're in the zone, man */

  while (wildpos <= zplen)
  {
    for (;;)
    {
      shibari_tdb_entry entry ;
      int r = shibari_tdb_read_entry(tdb, &state, &entry, q->s + wildpos, q->len + wildpos, qtype, !!wildpos, loc, stamp, &flagyxdomain) ;
      if (r == -1) return 2 ;
      if (!r) break ;
      if (!shibari_packet_add_rr(pkt, &entry, 0, 0, 2))
      {
        pkt->hdr.tc = 1 ;
        return 0 ;
      }
      switch (entry.type)
      {
        case SHIBARI_T_NS :
        case SHIBARI_T_MX :
        case SHIBARI_T_CNAME :  /* we're not supposed to but meh */
          gluetype = entry.type ;
        default : break ;
      }
    }
    if (pkt->hdr.counts.an) break ;
    wildpos += 1 + q->s[wildpos] ;
  }

  if (!flagyxdomain) pkt->hdr.rcode = 3 ;

  if (!pkt->hdr.counts.an)
  {
    unsigned int r = shibari_packet_assert_authority(pkt, tdb, q->s + zplen, q->len - zplen, zplen, loc, stamp) ;
    if (r) return r ;
  }
  else if (gluetype)
  {
    unsigned int r = shibari_packet_add_glue(pkt, tdb, q->s, q->len, gluetype, q->s + zplen, q->len - zplen, zplen, wildpos, loc, stamp) ;
    if (r) return r ;
  }

  shibari_packet_end(pkt) ;
  return rcode ;
}
