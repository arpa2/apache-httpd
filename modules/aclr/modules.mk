mod_aclr.la: mod_aclr.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_aclr.lo $(MOD_ACLR_LDADD)
DISTCLEAN_TARGETS = modules.mk
static = 
shared =  mod_aclr.la
