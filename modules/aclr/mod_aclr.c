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
#include "arch/unix/apr_arch_networkio.h"


module AP_MODULE_DECLARE_DATA aclr_module;

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

typedef struct {
} aclr_server_config;

/*
 * Locate our server configuration record for the specified server.
 */
static aclr_server_config *our_sconfig(const server_rec *s)
{
    return (aclr_server_config *) ap_get_module_config(s->module_config, &aclr_module);
}

static aclr_server_config* pMainConfig;

static void *create_aclr_server_config(apr_pool_t *p, server_rec *s)
{
   aclr_server_config *pConfig = apr_pcalloc(p, sizeof *pConfig);

//    pConfig->bEnabled = 0;
//    pConfig->nVerifyClient = SSL_CVERIFY_NONE;

    char *note = apr_psprintf(p, "create_aclr_server_config: server_hostname = %s", s->server_hostname);
    if (s->server_hostname == NULL) {
        pMainConfig = pConfig;
    }
    trace_nocontext(p, __FILE__, __LINE__, note);
    return pConfig;
}
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
    /*
     * Log the call and return OK, or access will be denied (even though we
     * didn't actually do anything).
     */
    char *note = apr_psprintf(r->pool, "x_check_authz()");
    trace_nocontext(r->pool, __FILE__, __LINE__, note);
    return DECLINED;
}

static void register_hooks(apr_pool_t *p)
{
    ap_hook_check_authz(x_check_authz, NULL, NULL, APR_HOOK_MIDDLE,
                        AP_AUTH_INTERNAL_PER_CONF);
}

AP_DECLARE_MODULE(aclr) = {
    STANDARD20_MODULE_STUFF,
    NULL,                          /* create per-directory config structure */
    NULL,                          /* merge per-directory config structures */
    create_aclr_server_config,     /* create per-server config structure */
    NULL,                          /* merge per-server config structures */
    NULL,                          /* command apr_table_t */
    register_hooks                 /* register hooks */
};
