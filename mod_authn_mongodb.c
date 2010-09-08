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

/*
 * http_auth: authentication
 *
 * Rob McCool & Brian Behlendorf.
 *
 * Adapted to Apache by rst.
 *
 */

#define APR_WANT_STRFUNC
#include "apr_want.h"
#include "apr_strings.h"
//#include "apr_dbm.h"
#include "apr_md5.h"        /* for apr_password_validate */
#include "apr_sha1.h"        /* for apr_password_validate */

#include "ap_provider.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"   /* for ap_hook_(check_user_id | auth_checker)*/

#include "mod_auth.h"

#include "mongo.h"
#include "bson.h"

typedef struct {
    char *host;
    int port;
    char *collection;
    char *userfield;
    char *passwdfield;
    char *password_format;
} authn_mongodb_config_rec;

static void *create_authn_mongodb_dir_config(apr_pool_t *p, char *d)
{
    authn_mongodb_config_rec *conf = apr_palloc(p, sizeof(*conf));

    conf->host= "127.0.0.1";
    conf->port= 27017;
    conf->collection="priv.auth_user";
    conf->userfield="username";
    conf->passwdfield="password";
    conf->password_format=NULL;

    return conf;
}

static const char *set_mongodb_port(cmd_parms *cmd,
                                void *dir_config,
                                const char *arg)
{
    authn_mongodb_config_rec *conf = dir_config;

    conf->port = atoi( arg);
    if (conf->port <=0) {
        return "invalid AuthMongoPort setting";
    }
    return NULL;
}

static const command_rec authn_mongodb_cmds[] =
{
    AP_INIT_TAKE1("AuthMongoHost", ap_set_string_slot,
     (void *)APR_OFFSETOF(authn_mongodb_config_rec, host),
     OR_AUTHCFG, "hostname to mongo database containing user IDs and passwords (default 127.0.0.1)"),

    AP_INIT_TAKE1("AuthMongoPort", set_mongodb_port,
     NULL,
     OR_AUTHCFG, "Port for mongoDB (default 27017)"),

    AP_INIT_TAKE1("AuthMongoCollection", ap_set_string_slot,
     (void *)APR_OFFSETOF(authn_mongodb_config_rec, collection),
     OR_AUTHCFG, "collection to query (default priv.auth_user)"),

    AP_INIT_TAKE1("AuthMongoUserField", ap_set_string_slot,
     (void *)APR_OFFSETOF(authn_mongodb_config_rec, userfield),
     OR_AUTHCFG, "collection to query (default username)"),

    AP_INIT_TAKE1("AuthMongoPasswordField", ap_set_string_slot,
     (void *)APR_OFFSETOF(authn_mongodb_config_rec, passwdfield),
     OR_AUTHCFG, "collection to query (default password)"),

    AP_INIT_TAKE1("AuthMongoFormatPassword", ap_set_string_slot,
     (void *)APR_OFFSETOF(authn_mongodb_config_rec, password_format),
     OR_AUTHCFG, "Set to 'Django' for passwords in django format. (default none)"),

    {NULL}
};

module AP_MODULE_DECLARE_DATA authn_mongodb_module;

static apr_status_t fetch_mongodb_value(const char *host, int port,
                                    const char *userfield, const char *passwordfield, const char *collection,
                                    const char *user, char **value,
                                    apr_pool_t *pool)
{
    mongo_connection conn; /* ptr */
    mongo_connection_options *opts;
    mongo_conn_return mongo_status;

    bson query[1];
    bson *out;
    bson_buffer query_buf[1];
    bson_bool_t found;
    mongo_cursor *cursor;
 
    *value = NULL;

    //conn = apr_palloc( pool, sizeof(mongo_connection));
    opts = apr_palloc( pool, sizeof(mongo_connection_options));
    strcpy( opts->host, host);
    opts->port = port;
    mongo_status = mongo_connect( pool, &conn, opts );

    if ( mongo_status != mongo_conn_success) {
        char buf[120];
        ap_log_perror(APLOG_MARK, APLOG_ERR, 0, pool,"couldn't connect to mongoDB - (%s)", mongo_strerror( mongo_status, buf,sizeof(buf) ));
        return APR_EGENERAL;
    }

    bson_buffer_init( pool, query_buf );
    bson_append_string( query_buf, userfield, user);
    bson_from_buffer( query, query_buf );
    out = apr_palloc(pool, sizeof(bson));
    found = mongo_find_one( &conn, collection, query, NULL, out );
    
    bson_destroy( query );
    if ( found ) {
        bson_iterator it;
        if (bson_find( &it, out, passwordfield )) {
//            bson_iterator iCookies;
//            bson_iterator_init( &iCookies , bson_iterator_value(&it));
            *value = apr_pstrdup( pool,bson_iterator_string(&it));
        }
    }
    mongo_destroy( &conn );

    return APR_SUCCESS;
}

/* from apr's uuid */
static unsigned char parse_hexpair(const char *s) 
{
    int result;
    int temp;

    result = s[0] - '0';
    if (result > 48) 
    result = (result - 39) << 4;
    else if (result > 16) 
    result = (result - 7) << 4;
    else
    result = result << 4;
    temp = s[1] - '0';
    if (temp > 48) 
    result |= temp - 39; 
    else if (temp > 16) 
    result |= temp - 7;
    else
    result |= temp;
    return (unsigned char)result;
}

static authn_status check_mongodb_pw(request_rec *r, const char *user,
                                 const char *password)
{
    authn_mongodb_config_rec *conf = ap_get_module_config(r->per_dir_config,
                                                      &authn_mongodb_module);
    apr_status_t rv;
    char *password_hash;
    char *colon_pw;

    rv = fetch_mongodb_value(conf->host, conf->port, 
            conf->userfield, conf->passwdfield, conf->collection, 
            user, &password_hash,
            r->pool);

    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                      "could not open mongoDB (host %s) port: %d",
                      conf->host, conf->port);
        return AUTH_GENERAL_ERROR;
    }

    if (!password_hash) {
        return AUTH_USER_NOT_FOUND;
    }

    if ( conf->password_format != NULL) {
       if ( strcasecmp( conf->password_format,"django")==0) {
            char *token;
            char *alg;
            char *salt;
            char *hsh;
            char *saltpass;
            alg= apr_strtok( password_hash, "$",&token);
            salt = apr_strtok( NULL, "$",&token);
            hsh = apr_strtok( NULL, "$",&token);
            //ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,"password_hash=%s ALG=%s salt=%s hsh=%s", password_hash,alg,salt,hsh );
            saltpass= apr_pstrcat(r->pool, salt, password, NULL);
            //char hash[APR_SHA1_DIGESTSIZE+APR_SHA1PW_IDLEN];
            apr_byte_t hash[APR_SHA1_DIGESTSIZE+1];
            apr_sha1_ctx_t context;
            apr_sha1_init(&context);
            apr_sha1_update(&context, saltpass, strlen(saltpass));
            apr_sha1_final(hash, &context);
            hash[APR_SHA1_DIGESTSIZE]='\0';
            int i=0;
            int j=0;
            for (i=0,j=0; i < APR_SHA1_DIGESTSIZE ;i+=1, j+=2 ) {
                if ( hash[i] != parse_hexpair(&(hsh[j]))) {
                    return AUTH_DENIED;
                }
            }
            return AUTH_GRANTED;
            
       } else {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,"unrecognized password format %s", conf->password_format);
            return AUTH_DENIED;
       }
    } else {
        colon_pw = ap_strchr(password_hash, ':');
        if (colon_pw) {
            *colon_pw = '\0';
        }
        rv = apr_password_validate(password, password_hash);
    }

    if (rv != APR_SUCCESS) {
        return AUTH_DENIED;
    }

    return AUTH_GRANTED;
}

static authn_status get_mongodb_realm_hash(request_rec *r, const char *user,
                                       const char *realm, char **rethash)
{
    authn_mongodb_config_rec *conf = ap_get_module_config(r->per_dir_config,
                                                      &authn_mongodb_module);
    apr_status_t rv;
    char *dbm_hash;
    char *colon_hash;

    rv = fetch_mongodb_value(conf->host, conf->port,
                         conf->userfield, conf->passwdfield, conf->collection, 
                         apr_pstrcat(r->pool, user, ":", realm, NULL),
                         &dbm_hash, r->pool);

    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                      "Could not open mongoDB (host %s) port : %d",
                      conf->host, conf->port);
        return AUTH_GENERAL_ERROR;
    }

    if (!dbm_hash) {
        return AUTH_USER_NOT_FOUND;
    }

    colon_hash = ap_strchr(dbm_hash, ':');
    if (colon_hash) {
        *colon_hash = '\0';
    }

    *rethash = dbm_hash;

    return AUTH_USER_FOUND;
}

static const authn_provider authn_mongodb_provider =
{
    &check_mongodb_pw,
    &get_mongodb_realm_hash
};

static void register_hooks(apr_pool_t *p)
{
    ap_register_provider(p, AUTHN_PROVIDER_GROUP, "mongodb", "0",
                         &authn_mongodb_provider);
}

module AP_MODULE_DECLARE_DATA authn_mongodb_module =
{
    STANDARD20_MODULE_STUFF,
    create_authn_mongodb_dir_config, /* dir config creater */
    NULL,                        /* dir merger --- default is to override */
    NULL,                        /* server config */
    NULL,                        /* merge server config */
    authn_mongodb_cmds,              /* command apr_table_t */
    register_hooks               /* register hooks */
};
