dnl modules enabled in this directory by default

dnl APACHE_MODULE(name, helptext[, objects[, structname[, default[, config]]]])

APACHE_MODPATH_INIT(aclr)

APACHE_MODULE(aclr, ACL resource control, , , yes)

APACHE_MODPATH_FINISH
