/* ====================================================================
 * Copyright (c) 1995-1997 The Apache Group.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the Apache Group
 *    for use in the Apache HTTP server project (http://www.apache.org/)."
 *
 * 4. The names "Apache Server" and "Apache Group" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission.
 *
 * 5. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the Apache Group
 *    for use in the Apache HTTP server project (http://www.apache.org/)."
 *
 * THIS SOFTWARE IS PROVIDED BY THE APACHE GROUP ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE APACHE GROUP OR
 * IT'S CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Group and was originally based
 * on public domain software written at the National Center for
 * Supercomputing Applications, University of Illinois, Urbana-Champaign.
 * For more information on the Apache Group and the Apache HTTP server
 * project, please see <http://www.apache.org/>.
 *
 */

/*
 * mod_cern_meta.c
 * version 0.1.0
 * status beta
 * 
 * Andrew Wilson <Andrew.Wilson@cm.cf.ac.uk> 25.Jan.96
 *
 * *** IMPORTANT ***
 * This version of mod_cern_meta.c controls Meta File behaviour on a
 * per-directory basis.  Previous versions of the module defined behaviour
 * on a per-server basis.  The upshot is that you'll need to revisit your 
 * configuration files in order to make use of the new module.
 * ***
 *
 * Emulate the CERN HTTPD Meta file semantics.  Meta files are HTTP
 * headers that can be output in addition to the normal range of
 * headers for each file accessed.  They appear rather like the Apache
 * .asis files, and are able to provide a crude way of influencing
 * the Expires: header, as well as providing other curiosities.
 * There are many ways to manage meta information, this one was
 * chosen because there is already a large number of CERN users
 * who can exploit this module.  It should be noted that there are probably
 * more sensitive ways of managing the Expires: header specifically.
 *
 * The module obeys the following directives, which can appear 
 * in the server's .conf files and in .htaccess files.
 *
 *  MetaFiles <on|off> 
 *
 *    turns on|off meta file processing for any directory.  
 *    Default value is off
 *
 *        # turn on MetaFiles in this directory
 *        MetaFiles on
 *
 *  MetaDir <directory name>
 *      
 *    specifies the name of the directory in which Apache can find
 *    meta information files.  The directory is usually a 'hidden'
 *    subdirectory of the directory that contains the file being
 *    accessed.  eg:
 *
 *        # .meta files are in the *same* directory as the 
 *        # file being accessed
 *        MetaDir .
 *
 *    the default is to look in a '.web' subdirectory. This is the
 *    same as for CERN 3.+ webservers and behaviour is the same as 
 *    for the directive:
 *
 *        MetaDir .web
 *
 *  MetaSuffix <meta file suffix>
 *
 *    specifies the file name suffix for the file containing the
 *    meta information.  eg:
 *
 *       # our meta files are suffixed with '.cern_meta'
 *       MetaSuffix .cern_meta
 *
 *    the default is to look for files with the suffix '.meta'.  This
 *    behaviour is the same as for the directive:
 *
 *       MetaSuffix .meta
 *
 * When accessing the file
 *
 *   DOCUMENT_ROOT/somedir/index.html
 *
 * this module will look for the file
 *
 *   DOCUMENT_ROOT/somedir/.web/index.html.meta
 *
 * and will use its contents to generate additional MIME header 
 * information.
 *
 * For more information on the CERN Meta file semantics see:
 *
 *   http://www.w3.org/hypertext/WWW/Daemon/User/Config/General.html#MetaDir
 *
 * Change-log:
 * 29.Jan.96 pfopen/pfclose instead of fopen/fclose
 *           DECLINE when real file not found, we may be checking each
 *           of the index.html/index.shtml/index.htm variants and don't
 *           need to report missing ones as spurious errors. 
 * 31.Jan.96 log_error reports about a malformed .meta file, rather
 *           than a script error.
 * 20.Jun.96 MetaFiles <on|off> default off, added, so that module
 *           can be configured per-directory.  Prior to this the module
 *           was running for each request anywhere on the server, naughty..
 * 29.Jun.96 All directives made per-directory.
 */

#include "httpd.h"
#include "http_config.h"
#include <sys/types.h>
#include <sys/stat.h>
#include "util_script.h"
#include "http_log.h"
#include "http_request.h"

#define DIR_CMD_PERMS OR_INDEXES

#define DEFAULT_METADIR		".web"
#define DEFAULT_METASUFFIX	".meta"
#define DEFAULT_METAFILES	0

module MODULE_VAR_EXPORT cern_meta_module;

typedef struct {
    char *metadir;
    char *metasuffix;
    char *metafiles;
} cern_meta_dir_config;

void *create_cern_meta_dir_config(pool *p, char *dummy)
{
    cern_meta_dir_config *new =
    (cern_meta_dir_config *) palloc(p, sizeof(cern_meta_dir_config));

    new->metadir = NULL;
    new->metasuffix = NULL;
    new->metafiles = DEFAULT_METAFILES;

    return new;
}

void *merge_cern_meta_dir_configs(pool *p, void *basev, void *addv)
{
    cern_meta_dir_config *base = (cern_meta_dir_config *) basev;
    cern_meta_dir_config *add = (cern_meta_dir_config *) addv;
    cern_meta_dir_config *new =
    (cern_meta_dir_config *) palloc(p, sizeof(cern_meta_dir_config));

    new->metadir = add->metadir ? add->metadir : base->metadir;
    new->metasuffix = add->metasuffix ? add->metasuffix : base->metasuffix;
    new->metafiles = add->metafiles;

    return new;
}

const char *set_metadir(cmd_parms *parms, cern_meta_dir_config * dconf, char *arg)
{
    dconf->metadir = arg;
    return NULL;
}

const char *set_metasuffix(cmd_parms *parms, cern_meta_dir_config * dconf, char *arg)
{
    dconf->metasuffix = arg;
    return NULL;
}

const char *set_metafiles(cmd_parms *parms, cern_meta_dir_config * dconf, char *arg)
{
    dconf->metafiles = arg;
    return NULL;
}


command_rec cern_meta_cmds[] =
{
    {"MetaFiles", set_metafiles, NULL, DIR_CMD_PERMS, FLAG, NULL},
    {"MetaDir", set_metadir, NULL, DIR_CMD_PERMS, TAKE1,
     "the name of the directory containing meta files"},
    {"MetaSuffix", set_metasuffix, NULL, DIR_CMD_PERMS, TAKE1,
     "the filename suffix for meta files"},
    {NULL}
};

int scan_meta_file(request_rec *r, FILE *f)
{
    char w[MAX_STRING_LEN];
    char *l;
    int p;

    while (fgets(w, MAX_STRING_LEN - 1, f) != NULL) {

	/* Delete terminal (CR?)LF */

	p = strlen(w);
	if (p > 0 && w[p - 1] == '\n') {
	    if (p > 1 && w[p - 2] == '\015')
		w[p - 2] = '\0';
	    else
		w[p - 1] = '\0';
	}

	if (w[0] == '\0') {
	    return OK;
	}

	/* if we see a bogus header don't ignore it. Shout and scream */

	if (!(l = strchr(w, ':'))) {
	    aplog_error(APLOG_MARK, APLOG_ERR, r->server,
			"malformed header in meta file: %s", r->filename);
	    return SERVER_ERROR;
	}

	*l++ = '\0';
	while (*l && isspace(*l))
	    ++l;

	if (!strcasecmp(w, "Content-type")) {

	    /* Nuke trailing whitespace */

	    char *endp = l + strlen(l) - 1;
	    while (endp > l && isspace(*endp))
		*endp-- = '\0';

	    r->content_type = pstrdup(r->pool, l);
	}
	else if (!strcasecmp(w, "Status")) {
	    sscanf(l, "%d", &r->status);
	    r->status_line = pstrdup(r->pool, l);
	}
	else {
	    table_set(r->headers_out, w, l);
	}
    }
    return OK;
}

int add_cern_meta_data(request_rec *r)
{
    char *metafilename;
    char *last_slash;
    char *real_file;
    char *scrap_book;
    FILE *f;
    cern_meta_dir_config *dconf;
    int rv;
    request_rec *rr;

    dconf = get_module_config(r->per_dir_config, &cern_meta_module);

    if (!dconf->metafiles) {
	return DECLINED;
    };

    /* if ./.web/$1.meta exists then output 'asis' */

    if (r->finfo.st_mode == 0) {
	return DECLINED;
    };

    /* is this a directory? */
    if (S_ISDIR(r->finfo.st_mode) || r->uri[strlen(r->uri) - 1] == '/') {
	return DECLINED;
    };

    /* what directory is this file in? */
    scrap_book = pstrdup(r->pool, r->filename);
    /* skip leading slash, recovered in later processing */
    scrap_book++;
    last_slash = strrchr(scrap_book, '/');
    if (last_slash != NULL) {
	/* skip over last slash */
	real_file = last_slash;
	real_file++;
	*last_slash = '\0';
    }
    else {
	/* no last slash, buh?! */
	aplog_error(APLOG_MARK, APLOG_ERR, r->server,
		    "internal error in mod_cern_meta", r->filename);
	/* should really barf, but hey, let's be friends... */
	return DECLINED;
    };

    metafilename = pstrcat(r->pool, "/", scrap_book, "/",
			   dconf->metadir ? dconf->metadir : DEFAULT_METADIR,
			   "/", real_file,
		 dconf->metasuffix ? dconf->metasuffix : DEFAULT_METASUFFIX,
			   NULL);

    /* XXX: it sucks to require this subrequest to complete, because this
     * means people must leave their meta files accessible to the world.
     * A better solution might be a "safe open" feature of pfopen to avoid
     * pipes, symlinks, and crap like that.
     */
    rr = sub_req_lookup_file(metafilename, r);
    if (rr->status != HTTP_OK) {
	destroy_sub_req(rr);
	return DECLINED;
    }
    destroy_sub_req(rr);

    f = pfopen(r->pool, metafilename, "r");
    if (f == NULL) {
	if (errno == ENOENT) {
	    return DECLINED;
	}
	aplog_error(APLOG_MARK, APLOG_ERR, r->server,
	      "meta file permissions deny server access: %s", metafilename);
	return FORBIDDEN;
    };

    /* read the headers in */
    rv = scan_meta_file(r, f);
    pfclose(r->pool, f);

    return rv;
}

module MODULE_VAR_EXPORT cern_meta_module =
{
    STANDARD_MODULE_STUFF,
    NULL,			/* initializer */
    create_cern_meta_dir_config,	/* dir config creater */
    merge_cern_meta_dir_configs,	/* dir merger --- default is to override */
    NULL,			/* server config */
    NULL,			/* merge server configs */
    cern_meta_cmds,		/* command table */
    NULL,			/* handlers */
    NULL,			/* filename translation */
    NULL,			/* check_user_id */
    NULL,			/* check auth */
    NULL,			/* check access */
    NULL,			/* type_checker */
    add_cern_meta_data,		/* fixups */
    NULL,			/* logger */
    NULL,			/* header parser */
    NULL,			/* child_init */
    NULL,			/* child_exit */
    NULL			/* post read-request */
};
