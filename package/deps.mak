#
# This file has been generated by tools/gen-deps.sh
#

src/include/shibari/cache.h: src/include/shibari/dcache.h
src/include/shibari/common.h: src/include/shibari/constants.h src/include/shibari/util.h
src/include/shibari/packet.h: src/include/shibari/tdb.h
src/include/shibari/server.h: src/include/shibari/log.h src/include/shibari/packet.h src/include/shibari/tdb.h
src/include/shibari/shibari.h: src/include/shibari/cache.h src/include/shibari/client.h src/include/shibari/common.h src/include/shibari/server.h
src/cache/dcache-internal.h: src/include/shibari/dcache.h
src/cache/dcache_add.o src/cache/dcache_add.lo: src/cache/dcache_add.c src/cache/dcache-internal.h src/include/shibari/dcache.h
src/cache/dcache_clean_expired.o src/cache/dcache_clean_expired.lo: src/cache/dcache_clean_expired.c src/cache/dcache-internal.h src/include/shibari/dcache.h
src/cache/dcache_delete.o src/cache/dcache_delete.lo: src/cache/dcache_delete.c src/cache/dcache-internal.h src/include/shibari/dcache.h
src/cache/dcache_free.o src/cache/dcache_free.lo: src/cache/dcache_free.c src/include/shibari/dcache.h
src/cache/dcache_init.o src/cache/dcache_init.lo: src/cache/dcache_init.c src/include/shibari/dcache.h
src/cache/dcache_load.o src/cache/dcache_load.lo: src/cache/dcache_load.c src/include/shibari/dcache.h
src/cache/dcache_save.o src/cache/dcache_save.lo: src/cache/dcache_save.c src/include/shibari/dcache.h
src/cache/dcache_search.o src/cache/dcache_search.lo: src/cache/dcache_search.c src/cache/dcache-internal.h src/include/shibari/dcache.h
src/cache/shibari-cache.o src/cache/shibari-cache.lo: src/cache/shibari-cache.c src/include/shibari/cache.h src/include/shibari/common.h
src/common/shibari_log_answer.o src/common/shibari_log_answer.lo: src/common/shibari_log_answer.c src/include/shibari/log.h src/include/shibari/util.h
src/common/shibari_log_exit.o src/common/shibari_log_exit.lo: src/common/shibari_log_exit.c src/include/shibari/log.h
src/common/shibari_log_query.o src/common/shibari_log_query.lo: src/common/shibari_log_query.c src/include/shibari/log.h src/include/shibari/util.h
src/common/shibari_log_queryplus.o src/common/shibari_log_queryplus.lo: src/common/shibari_log_queryplus.c src/include/shibari/log.h src/include/shibari/util.h
src/common/shibari_log_start.o src/common/shibari_log_start.lo: src/common/shibari_log_start.c src/include/shibari/log.h
src/common/shibari_util_canon_domain.o src/common/shibari_util_canon_domain.lo: src/common/shibari_util_canon_domain.c src/include/shibari/util.h
src/common/shibari_util_get_prefixlen.o src/common/shibari_util_get_prefixlen.lo: src/common/shibari_util_get_prefixlen.c src/include/shibari/util.h
src/common/shibari_util_qtype_num.o src/common/shibari_util_qtype_num.lo: src/common/shibari_util_qtype_num.c src/include/shibari/util.h
src/common/shibari_util_qtype_str.o src/common/shibari_util_qtype_str.lo: src/common/shibari_util_qtype_str.c src/include/shibari/util.h
src/common/shibari_util_rcode_str.o src/common/shibari_util_rcode_str.lo: src/common/shibari_util_rcode_str.c src/include/shibari/util.h
src/config/conftree.o src/config/conftree.lo: src/config/conftree.c src/config/shibari-cache-config-internal.h
src/config/defaults.o src/config/defaults.lo: src/config/defaults.c src/config/shibari-cache-config-internal.h
src/config/lexparse.o src/config/lexparse.lo: src/config/lexparse.c src/config/shibari-cache-config-internal.h src/include/shibari/config.h
src/config/node.o src/config/node.lo: src/config/node.c src/config/shibari-cache-config-internal.h
src/config/repo.o src/config/repo.lo: src/config/repo.c src/config/shibari-cache-config-internal.h
src/config/shibari-cache-config.o src/config/shibari-cache-config.lo: src/config/shibari-cache-config.c src/config/shibari-cache-config-internal.h src/include/shibari/config.h
src/config/util.o src/config/util.lo: src/config/util.c src/config/shibari-cache-config-internal.h
src/server/shibari-server-tcp.o src/server/shibari-server-tcp.lo: src/server/shibari-server-tcp.c src/include/shibari/common.h src/include/shibari/server.h
src/server/shibari-server-udp.o src/server/shibari-server-udp.lo: src/server/shibari-server-udp.c src/include/shibari/common.h src/include/shibari/server.h
src/server/shibari_packet_add_glue.o src/server/shibari_packet_add_glue.lo: src/server/shibari_packet_add_glue.c src/include/shibari/constants.h src/include/shibari/packet.h src/include/shibari/tdb.h src/include/shibari/util.h
src/server/shibari_packet_add_rr.o src/server/shibari_packet_add_rr.lo: src/server/shibari_packet_add_rr.c src/include/shibari/constants.h src/include/shibari/packet.h
src/server/shibari_packet_assert_authority.o src/server/shibari_packet_assert_authority.lo: src/server/shibari_packet_assert_authority.c src/include/shibari/constants.h src/include/shibari/packet.h src/include/shibari/tdb.h src/include/shibari/util.h
src/server/shibari_packet_begin.o src/server/shibari_packet_begin.lo: src/server/shibari_packet_begin.c src/include/shibari/constants.h src/include/shibari/packet.h
src/server/shibari_packet_end.o src/server/shibari_packet_end.lo: src/server/shibari_packet_end.c src/include/shibari/packet.h
src/server/shibari_packet_init.o src/server/shibari_packet_init.lo: src/server/shibari_packet_init.c src/include/shibari/packet.h
src/server/shibari_packet_tdb_answer_query.o src/server/shibari_packet_tdb_answer_query.lo: src/server/shibari_packet_tdb_answer_query.c src/include/shibari/constants.h src/include/shibari/packet.h src/include/shibari/tdb.h src/include/shibari/util.h
src/server/shibari_packet_tdb_axfr.o src/server/shibari_packet_tdb_axfr.lo: src/server/shibari_packet_tdb_axfr.c src/include/shibari/constants.h src/include/shibari/packet.h src/include/shibari/tdb.h src/include/shibari/util.h
src/server/shibari_tdb_entry_parse.o src/server/shibari_tdb_entry_parse.lo: src/server/shibari_tdb_entry_parse.c src/include/shibari/constants.h src/include/shibari/tdb.h
src/server/shibari_tdb_extract_domain.o src/server/shibari_tdb_extract_domain.lo: src/server/shibari_tdb_extract_domain.c src/include/shibari/constants.h src/include/shibari/tdb.h
src/server/shibari_tdb_find_authority.o src/server/shibari_tdb_find_authority.lo: src/server/shibari_tdb_find_authority.c src/include/shibari/constants.h src/include/shibari/tdb.h
src/server/shibari_tdb_read_entry.o src/server/shibari_tdb_read_entry.lo: src/server/shibari_tdb_read_entry.c src/include/shibari/tdb.h

ifeq ($(strip $(STATIC_LIBS_ARE_PIC)),)
libdcache.a.xyzzy: src/cache/dcache_add.o src/cache/dcache_clean_expired.o src/cache/dcache_delete.o src/cache/dcache_free.o src/cache/dcache_init.o src/cache/dcache_load.o src/cache/dcache_save.o src/cache/dcache_search.o
else
libdcache.a.xyzzy: src/cache/dcache_add.lo src/cache/dcache_clean_expired.lo src/cache/dcache_delete.lo src/cache/dcache_free.lo src/cache/dcache_init.lo src/cache/dcache_load.lo src/cache/dcache_save.lo src/cache/dcache_search.lo
endif
libdcache.so.xyzzy: EXTRA_LIBS :=
libdcache.so.xyzzy: src/cache/dcache_add.lo src/cache/dcache_clean_expired.lo src/cache/dcache_delete.lo src/cache/dcache_free.lo src/cache/dcache_init.lo src/cache/dcache_load.lo src/cache/dcache_save.lo src/cache/dcache_search.lo
ifeq ($(strip $(STATIC_LIBS_ARE_PIC)),)
libshibari-common.a.xyzzy: src/common/shibari_log_answer.o src/common/shibari_log_exit.o src/common/shibari_log_query.o src/common/shibari_log_queryplus.o src/common/shibari_log_start.o src/common/shibari_util_qtype_num.o src/common/shibari_util_qtype_str.o src/common/shibari_util_rcode_str.o src/common/shibari_util_canon_domain.o src/common/shibari_util_get_prefixlen.o
else
libshibari-common.a.xyzzy: src/common/shibari_log_answer.lo src/common/shibari_log_exit.lo src/common/shibari_log_query.lo src/common/shibari_log_queryplus.lo src/common/shibari_log_start.lo src/common/shibari_util_qtype_num.lo src/common/shibari_util_qtype_str.lo src/common/shibari_util_rcode_str.lo src/common/shibari_util_canon_domain.lo src/common/shibari_util_get_prefixlen.lo
endif
libshibari-common.so.xyzzy: EXTRA_LIBS := -ls6dns -lskarnet
libshibari-common.so.xyzzy: src/common/shibari_log_answer.lo src/common/shibari_log_exit.lo src/common/shibari_log_query.lo src/common/shibari_log_queryplus.lo src/common/shibari_log_start.lo src/common/shibari_util_qtype_num.lo src/common/shibari_util_qtype_str.lo src/common/shibari_util_rcode_str.lo src/common/shibari_util_canon_domain.lo src/common/shibari_util_get_prefixlen.lo
shibari-cache-config: EXTRA_LIBS := -ls6dns -lskarnet
shibari-cache-config: src/config/shibari-cache-config.o src/config/util.o src/config/node.o src/config/repo.o src/config/conftree.o src/config/defaults.o src/config/lexparse.o
ifeq ($(strip $(STATIC_LIBS_ARE_PIC)),)
libshibari-server.a.xyzzy: src/server/shibari_packet_init.o src/server/shibari_packet_begin.o src/server/shibari_packet_end.o src/server/shibari_packet_add_rr.o src/server/shibari_tdb_entry_parse.o src/server/shibari_tdb_extract_domain.o src/server/shibari_tdb_find_authority.o src/server/shibari_tdb_read_entry.o src/server/shibari_packet_add_glue.o src/server/shibari_packet_assert_authority.o src/server/shibari_packet_tdb_answer_query.o src/server/shibari_packet_tdb_axfr.o
else
libshibari-server.a.xyzzy: src/server/shibari_packet_init.lo src/server/shibari_packet_begin.lo src/server/shibari_packet_end.lo src/server/shibari_packet_add_rr.lo src/server/shibari_tdb_entry_parse.lo src/server/shibari_tdb_extract_domain.lo src/server/shibari_tdb_find_authority.lo src/server/shibari_tdb_read_entry.lo src/server/shibari_packet_add_glue.lo src/server/shibari_packet_assert_authority.lo src/server/shibari_packet_tdb_answer_query.lo src/server/shibari_packet_tdb_axfr.lo
endif
libshibari-server.so.xyzzy: EXTRA_LIBS := -ls6dns -lskarnet
libshibari-server.so.xyzzy: src/server/shibari_packet_init.lo src/server/shibari_packet_begin.lo src/server/shibari_packet_end.lo src/server/shibari_packet_add_rr.lo src/server/shibari_tdb_entry_parse.lo src/server/shibari_tdb_extract_domain.lo src/server/shibari_tdb_find_authority.lo src/server/shibari_tdb_read_entry.lo src/server/shibari_packet_add_glue.lo src/server/shibari_packet_assert_authority.lo src/server/shibari_packet_tdb_answer_query.lo src/server/shibari_packet_tdb_axfr.lo
shibari-server-tcp: EXTRA_LIBS := -ls6dns -lskarnet
shibari-server-tcp: src/server/shibari-server-tcp.o ${LIBSHIBARI_SERVER} ${LIBSHIBARI_COMMON}
shibari-server-udp: EXTRA_LIBS := -ls6dns -ls6 -lskarnet ${SOCKET_LIB}
shibari-server-udp: src/server/shibari-server-udp.o ${LIBSHIBARI_SERVER} ${LIBSHIBARI_COMMON}
