dnl modules enabled in this directory by default

dnl APACHE_MODULE(name, helptext[, objects[, structname[, default[, config]]]])

APACHE_MODPATH_INIT(tlspool)

APACHE_MODULE(tlspool, TLS support using tlspool, , , yes, [ APR_ADDTO(MOD_TLSPOOL_LDADD, [ -ltlspool ]) ])

APACHE_MODPATH_FINISH
