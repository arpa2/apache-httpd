mod_tlspool.la: mod_tlspool.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_tlspool.lo $(MOD_TLSPOOL_LDADD)
DISTCLEAN_TARGETS = modules.mk
static = 
shared =  mod_tlspool.la
