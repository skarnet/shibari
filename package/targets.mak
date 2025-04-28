BIN_TARGETS := \
shibari-server-tcp \
shibari-server-udp \
# shibari-cache \
shibari-cache-config

LIBEXEC_TARGETS :=

LIB_DEFS := SHIBARI_SERVER=shibari-server SHIBARI_COMMON=shibari-common DCACHE=dcache
SHIBARI_SERVER_DESCRIPTION := helpers to implement a DNS server
SHIBARI_COMMON_DESCRIPTION := common functions to the shibari DNS software
DCACHE_DESCRIPTION := A library to implement a cache for DNS entries
