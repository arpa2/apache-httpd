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

#include "apr_strings.h"
#include "arch/unix/apr_arch_networkio.h"

#include <tlspool/starttls.h>

module AP_MODULE_DECLARE_DATA tlspool_module;

static starttls_t tlsdata_srv = {
        .flags = PIOF_STARTTLS_LOCALROLE_SERVER
                | PIOF_STARTTLS_REMOTEROLE_CLIENT,
        .local = 0,
        .ipproto = IPPROTO_TCP,
        .localid = "testsrv@tlspool.arpa2.lab",
        .service = "generic",
};
static starttls_t tlsdata_now;

typedef struct {
    int bEnabled;
} tlspool_config;

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

/*
 * Locate our server configuration record for the specified server.
 */
static tlspool_config *our_sconfig(const server_rec *s)
{
    return (tlspool_config *) ap_get_module_config(s->module_config, &tlspool_module);
}

static void *create_tlspool_server_config(apr_pool_t *p, server_rec *s)
{
    tlspool_config *pConfig = apr_pcalloc(p, sizeof *pConfig);

    pConfig->bEnabled = 0;

    return pConfig;
}

static const char *tlspool_on(cmd_parms *cmd, void *dummy, int arg)
{
    tlspool_config *pConfig = our_sconfig(cmd->server);
    pConfig->bEnabled = arg;
    return NULL;
}

/*
 * This routine is called just after the server accepts the connection,
 * but before it is handed off to a protocol module to be served.  The point
 * of this hook is to allow modules an opportunity to modify the connection
 * as soon as possible. The core server uses this phase to setup the
 * connection record based on the type of connection that is being used.
 *
 * This is a RUN_ALL hook.
 */
static int tlspool_pre_connection(conn_rec *c, void *csd)
{
    tlspool_config *pConfig = our_sconfig(c->base_server);
    if (pConfig->bEnabled) {
        char *note;
        apr_socket_t *apr_socket = (apr_socket_t *) csd;
        int cnx = apr_socket->socketdes;
        int plainfd = -1;

        tlsdata_now = tlsdata_srv;
        if (-1 == tlspool_starttls (cnx, &tlsdata_now, &plainfd, NULL)) {
            trace_nocontext(c->pool, __FILE__, __LINE__, "Failed to STARTTLS on Apache");
            if (plainfd >= 0) {
                close (plainfd);
            }
            exit (1);
        }
        apr_socket->socketdes = plainfd;

        /*
         * Log the call and exit.
         */
        note = apr_psprintf(c->pool, "tlspool_pre_connection: c = %pp, pool = %pp, old = %d, new = %d",
                        (void*) c, (void*) c->pool, cnx, plainfd);
        trace_nocontext(c->pool, __FILE__, __LINE__, note);
    } else {
        trace_nocontext(c->pool, __FILE__, __LINE__, "tlspool_pre_connection: TLSPoolEnable off");
    }
    return OK;
}

static const command_rec tlspool_cmds[] =
{
    AP_INIT_FLAG("TLSPoolEnable", tlspool_on, NULL, RSRC_CONF,
                 "Run a tlspool server on this host"),
    { NULL }
};

static void register_hooks(apr_pool_t *p)
{
    ap_hook_pre_connection(tlspool_pre_connection, NULL, NULL, APR_HOOK_MIDDLE);
}

AP_DECLARE_MODULE(tlspool) = {
    STANDARD20_MODULE_STUFF,
    NULL,                          /* create per-directory config structure */
    NULL,                          /* merge per-directory config structures */
    create_tlspool_server_config,  /* create per-server config structure */
    NULL,                          /* merge per-server config structures */
    tlspool_cmds,                  /* command apr_table_t */
    register_hooks                 /* register hooks */
};
