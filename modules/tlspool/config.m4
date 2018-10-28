dnl modules enabled in this directory by default

dnl APACHE_MODULE(name, helptext[, objects[, structname[, default[, config]]]])

APACHE_MODPATH_INIT(tlspool)

APACHE_MODULE(tlspool, TLS support using tlspool, , , )

APACHE_MODPATH_FINISH
