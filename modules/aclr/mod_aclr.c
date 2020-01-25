/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "ap_config.h"
#include "ap_mmn.h"
#include "httpd.h"
#include "http_config.h"
#include "http_connection.h"
#include "http_core.h"
#include "http_log.h"
#include "http_vhost.h"
#include "http_request.h"
#include "apr_strings.h"

#include <arpa2/a2aclr.h>

#define ACL_GET                       'R'
#define ACL_HEAD                      'P'
#define ACL_POST                      'C'
#define ACL_PUT                       'W'
#define ACL_DELETE                    'D'
#define ACL_PATCH                     'W'

#define HTTPUUID "7a35d76d-a754-35a6-abe7-757c161f0263"

module AP_MODULE_DECLARE_DATA aclr_module;

typedef struct {
    char *dbpath;
    void *ctx;
} aclr_dir_config;

typedef enum {
    cmd_dbpath
} cmd_parts;

static void trace_nocontext(apr_pool_t *p, const char *file, int line,
                            const char *note)
{
    /*
     * Since we have no request or connection to trace, or any idea
     * from where this routine was called, there's really not much we
     * can do.  If we are not logging everything by way of the
     * EXAMPLE_LOG_EACH constant, do nothing in this routine.
     */

    ap_log_perror(file, line, APLOG_MODULE_INDEX, APLOG_NOTICE, 0, p,
                  APLOGNO(03297) "%s", note);
}

static void *create_aclr_dir_config(apr_pool_t *p, char *dirspec)
{
    aclr_dir_config *pConfig = apr_pcalloc(p, sizeof *pConfig);

    char *note = apr_psprintf(p, "create_aclr_dir_config(p == %pp, dirspec == %s)",
                        (void*) p, dirspec);
    trace_nocontext(p, __FILE__, __LINE__, note);
    return pConfig;
}

/*
 * Locate our directory configuration record for the current request.
 */
static aclr_dir_config *our_dconfig(const request_rec *r)
{
    return (aclr_dir_config *) ap_get_module_config(r->per_dir_config, &aclr_module);
}

static const char *aclr_param(cmd_parms *cmd, void *dconf, const char *val)
{
    aclr_dir_config *pConfig = (aclr_dir_config *) dconf; 
    char errstr[200];
    ssize_t updated;

    switch ((long) cmd->info) {
    case cmd_dbpath:
        pConfig->dbpath = apr_pstrdup(cmd->pool, val);
        char *note = apr_psprintf(cmd->pool, "aclr_param: dbpath = %s", pConfig->dbpath);
        trace_nocontext(cmd->pool, __FILE__, __LINE__, note);
        pConfig->ctx = a2aclr_dbopen(NULL);
        if (pConfig->ctx == NULL) {
            trace_nocontext(cmd->pool, __FILE__, __LINE__, "failed to open new database context");
            return NULL;
        }
        updated = a2aclr_importpolicyfile(pConfig->ctx, pConfig->dbpath, errstr, sizeof(errstr));
        if (updated == -1) {
            note = apr_psprintf(cmd->pool, "failed to import policy file %s: %s", pConfig->dbpath, errstr);
            trace_nocontext(cmd->pool, __FILE__, __LINE__, note);
            return NULL;
        }
        note = apr_psprintf(cmd->pool, "%s initialized with %d new rules", pConfig->dbpath, updated);
        trace_nocontext(cmd->pool, __FILE__, __LINE__, note);
        break;
    }
    return NULL;
}

static const command_rec aclr_cmds[] = {
    AP_INIT_TAKE1("DBPath", aclr_param, (void*)cmd_dbpath, OR_AUTHCFG,
                  "Path of policy file"),
    {NULL}
};

/*
 * This routine is called to check to see if the resource being requested
 * requires authorisation.
 *
 * This is a RUN_FIRST hook. The return value is OK, DECLINED, or
 * HTTP_mumble.  If we return OK, no other modules are called during this
 * phase.
 *
 * If *all* modules return DECLINED, the request is aborted with a server
 * error.
 */
static int x_check_authz(request_rec *r)
{
    char reqright;
    aclr_dir_config *dconf;

    /*
     * Log the call and return OK, or access will be denied (even though we
     * didn't actually do anything).
     */
    const char *realm = ap_auth_name(r);
    char *remote_user = r->user;
    char *uri = r->uri;
    char *note = apr_psprintf(r->pool, "x_check_authz(): user = %s, uri = %s, realm = %s, ap_auth_type = %s, method = %s",
                    remote_user, uri, realm, r->ap_auth_type, r->method);
    trace_nocontext(r->pool, __FILE__, __LINE__, note);
    switch (r->method_number) {
    case M_GET:
        reqright = ACL_GET;
        break;
/* no M_HEAD?
    case M_HEAD:
        reqright = ACL_HEAD;
        break;
*/
    case M_POST:
        reqright = ACL_POST;
        break;
    case M_PUT:
        reqright = ACL_PUT;
        break;
    case M_DELETE:
        reqright = ACL_DELETE;
        break;
    default:
        reqright = ACL_GET;
    }
    dconf = our_dconfig(r);
    note = apr_psprintf(r->pool, "looking up %c in %s, ctx: %pp", reqright, dconf->dbpath, dconf->ctx);
    trace_nocontext(r->pool, __FILE__, __LINE__, note);
    if (dconf->ctx == NULL || a2aclr_hasright(dconf->ctx, reqright, realm, strlen(realm),
        remote_user, strlen(remote_user), HTTPUUID, sizeof(HTTPUUID) - 1,
        "", 0) == 0) {
        note = apr_psprintf(r->pool, "%c: FORBIDDEN", reqright);
        trace_nocontext(r->pool, __FILE__, __LINE__, note);
//      r->keepalive = 0;
//      r->preserve_body = 0;
        return HTTP_FORBIDDEN;
    }
    note = apr_psprintf(r->pool, "%c: PERMITTED", reqright);
    trace_nocontext(r->pool, __FILE__, __LINE__, note);
    return OK;
}

static void register_hooks(apr_pool_t *p)
{
    ap_hook_check_authz(x_check_authz, NULL, NULL, APR_HOOK_MIDDLE,
                        AP_AUTH_INTERNAL_PER_CONF);
}

AP_DECLARE_MODULE(aclr) = {
    STANDARD20_MODULE_STUFF,
    create_aclr_dir_config,        /* create per-directory config structure */
    NULL,                          /* merge per-directory config structures */
    NULL,                          /* create per-server config structure */
    NULL,                          /* merge per-server config structures */
    aclr_cmds,                     /* command apr_table_t */
    register_hooks                 /* register hooks */
};
