/* Copyright (c) 2013-2017 the Civetweb developers
 * Copyright (c) 2004-2013 Sergey Lyubka
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#ifndef CIVETWEB_HEADER_INCLUDED
#define CIVETWEB_HEADER_INCLUDED

#define CIVETWEB_VERSION "1.11"
#define CIVETWEB_VERSION_MAJOR (1)
#define CIVETWEB_VERSION_MINOR (11)
#define CIVETWEB_VERSION_PATCH (0)

#ifndef CIVETWEB_API
#if defined(_WIN32)
#if defined(CIVETWEB_DLL_EXPORTS)
#define CIVETWEB_API __declspec(dllexport)
#elif defined(CIVETWEB_DLL_IMPORTS)
#define CIVETWEB_API __declspec(dllimport)
#else
#define CIVETWEB_API
#endif
#elif __GNUC__ >= 4
#define CIVETWEB_API __attribute__((visibility("default")))
#else
#define CIVETWEB_API
#endif
#endif

#include <stddef.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */


/* Init Features */
enum {
	MG_FEATURES_DEFAULT = 0x0u,

	/* Support files from local directories */
	/* Will only work, if NO_FILES is not set. */
			MG_FEATURES_FILES = 0x1u,

	/* Support transport layer security (TLS). */
	/* SSL is still often used synonymously for TLS. */
	/* Will only work, if NO_SSL is not set. */
			MG_FEATURES_TLS = 0x2u,
	MG_FEATURES_SSL = 0x2u,

	/* Support common gateway interface (CGI). */
	/* Will only work, if NO_CGI is not set. */
			MG_FEATURES_CGI = 0x4u,

	/* Support IPv6. */
	/* Will only work, if USE_IPV6 is set. */
			MG_FEATURES_IPV6 = 0x8u,

	/* Support WebSocket protocol. */
	/* Will only work, if USE_WEBSOCKET is set. */
			MG_FEATURES_WEBSOCKET = 0x10u,

	/* Support server side Lua scripting. */
	/* Will only work, if USE_LUA is set. */
			MG_FEATURES_LUA = 0x20u,

	/* Support server side JavaScript scripting. */
	/* Will only work, if USE_DUKTAPE is set. */
			MG_FEATURES_SSJS = 0x40u,

	/* Provide data required for caching files. */
	/* Will only work, if NO_CACHING is not set. */
			MG_FEATURES_CACHE = 0x80u,

	/* Collect server status information. */
	/* Will only work, if USE_SERVER_STATS is set. */
			MG_FEATURES_STATS = 0x100u,

	/* Support on-the-fly compression. */
	/* Will only work, if USE_ZLIB is set. */
			MG_FEATURES_COMPRESSION = 0x200u,

	/* Collect server status information. */
	/* Will only work, if USE_SERVER_STATS is set. */
			MG_FEATURES_ALL = 0xFFFFu
};


/* Initialize this library. This should be called once before any other
 * function from this library. This function is not guaranteed to be
 * thread safe.
 * Parameters:
 *   features: bit mask for features to be initialized.
 *             Note: The TLS libraries (like OpenSSL) is initialized
 *                   only if the MG_FEATURES_TLS bit is set.
 *                   Currently the other bits do not influence
 *                   initialization, but this may change in future
 *                   versions.
 * Return value:
 *   initialized features
 *   0: error
 */
CIVETWEB_API unsigned mg_init_library(unsigned features);


/* Un-initialize this library.
 * Return value:
 *   0: error
 */
CIVETWEB_API unsigned mg_exit_library(void);


struct mg_context;    /* Handle for the HTTP service itself */
struct mg_connection; /* Handle for the individual connection */


/* Maximum number of headers */
#define MG_MAX_HEADERS (64)

struct mg_header {
	const char *name;  /* HTTP header name */
	const char *value; /* HTTP header value */
};


/* This structure contains information about the HTTP request. */
struct mg_request_info {
	const char *request_method;  /* "GET", "POST", etc */
	const char *request_uri;     /* URL-decoded URI (absolute or relative,
	                              * as in the request) */
	const char *local_uri;       /* URL-decoded URI (relative). Can be NULL
	                              * if the request_uri does not address a
	                              * resource at the server host. */
#if defined(MG_LEGACY_INTERFACE) /* 2017-02-04, deprecated 2014-09-14 */
	const char *uri;             /* Deprecated: use local_uri instead */
#endif
	const char *http_version; /* E.g. "1.0", "1.1" */
	const char *query_string; /* URL part after '?', not including '?', or
	                             NULL */
	const char *remote_user;  /* Authenticated user, or NULL if no auth
	                             used */
	char remote_addr[48];     /* Client's IP address as a string. */

	long long content_length; /* Length (in bytes) of the request body,
	                             can be -1 if no length was given. */
	int remote_port;          /* Client's port */
	int is_ssl;               /* 1 if SSL-ed, 0 if not */
	void *user_data;          /* User data pointer passed to mg_start() */
	void *conn_data;          /* Connection-specific user data */

	int num_headers; /* Number of HTTP headers */
	struct mg_header
			http_headers[MG_MAX_HEADERS]; /* Allocate maximum headers */

	struct mg_client_cert *client_cert; /* Client certificate information */

	const char *acceptedWebSocketSubprotocol; /* websocket subprotocol,
	                                           * accepted during handshake */
};
#endif



/* This structure contains information about the HTTP request. */
/* This structure may be extended in future versions. */
struct mg_response_info {
	int status_code;          /* E.g. 200 */
	const char *status_text;  /* E.g. "OK" */
	const char *http_version; /* E.g. "1.0", "1.1" */

	long long content_length; /* Length (in bytes) of the request body,
	                             can be -1 if no length was given. */

	int num_headers; /* Number of HTTP headers */
	struct mg_header
			http_headers[MG_MAX_HEADERS]; /* Allocate maximum headers */
};


/* Client certificate information (part of mg_request_info) */
/* New nomenclature. */
struct mg_client_cert {
	void *peer_cert;
	const char *subject;
	const char *issuer;
	const char *serial;
	const char *finger;
};

#if defined(MG_LEGACY_INTERFACE) /* 2017-10-05 */
/* Old nomenclature. */
struct client_cert {
	const char *subject;
	const char *issuer;
	const char *serial;
	const char *finger;
};
#endif


/* This structure needs to be passed to mg_start(), to let civetweb know
   which callbacks to invoke. For a detailed description, see
   https://github.com/civetweb/civetweb/blob/master/docs/UserManual.md */
struct mg_callbacks {
	/* Called when civetweb has received new HTTP request.
	   If the callback returns one, it must process the request
	   by sending valid HTTP headers and a body. Civetweb will not do
	   any further processing. Otherwise it must return zero.
	   Note that since V1.7 the "begin_request" function is called
	   before an authorization check. If an authorization check is
	   required, use a request_handler instead.
	   Return value:
	     0: civetweb will process the request itself. In this case,
	        the callback must not send any data to the client.
	     1-999: callback already processed the request. Civetweb will
	            not send any data after the callback returned. The
	            return code is stored as a HTTP status code for the
	            access log. */
	int (*begin_request)(struct mg_connection *);

	/* Called when civetweb has finished processing request. */
	void (*end_request)(const struct mg_connection *, int reply_status_code);

	/* Called when civetweb is about to log a message. If callback returns
	   non-zero, civetweb does not log anything. */
	int (*log_message)(const struct mg_connection *, const char *message);

	/* Called when civetweb is about to log access. If callback returns
	   non-zero, civetweb does not log anything. */
	int (*log_access)(const struct mg_connection *, const char *message);

	/* Called when civetweb initializes SSL library.
	   Parameters:
	     user_data: parameter user_data passed when starting the server.
	   Return value:
	     0: civetweb will set up the SSL certificate.
	     1: civetweb assumes the callback already set up the certificate.
	    -1: initializing ssl fails. */
	int (*init_ssl)(void *ssl_context, void *user_data);

	/* Called when civetweb is about to create or free a SSL_CTX.
	Parameters:
	   ssl_ctx: SSL_CTX pointer. NULL at creation time, Not NULL when mg_context
	            will be freed
	     user_data: parameter user_data passed when starting the server.
	   Return value:
	     0: civetweb will continue to create the context, just as if the
	        callback would not be present.
	        The value in *ssl_ctx when the function returns is ignored.
	     1: civetweb will copy the value from *ssl_ctx to the civetweb context
	        and doesn't create its own.
	    -1: initializing ssl fails.*/
	int (*external_ssl_ctx)(void **ssl_ctx, void *user_data);

#if defined(MG_LEGACY_INTERFACE) /* 2015-08-19 */
	/* Called when websocket request is received, before websocket handshake.
	   Return value:
	     0: civetweb proceeds with websocket handshake.
	     1: connection is closed immediately.
	   This callback is deprecated: Use mg_set_websocket_handler instead. */
	int (*websocket_connect)(const struct mg_connection *);

	/* Called when websocket handshake is successfully completed, and
	   connection is ready for data exchange.
	   This callback is deprecated: Use mg_set_websocket_handler instead. */
	void (*websocket_ready)(struct mg_connection *);

	/* Called when data frame has been received from the client.
	   Parameters:
	     bits: first byte of the websocket frame, see websocket RFC at
	           http://tools.ietf.org/html/rfc6455, section 5.2
	     data, data_len: payload, with mask (if any) already applied.
	   Return value:
	     1: keep this websocket connection open.
	     0: close this websocket connection.
	   This callback is deprecated: Use mg_set_websocket_handler instead. */
	int (*websocket_data)(struct mg_connection *,
	                      int bits,
	                      char *data,
	                      size_t data_len);
#endif /* MG_LEGACY_INTERFACE */

	/* Called when civetweb is closing a connection.  The per-context mutex is
	   locked when this is invoked.

	   Websockets:
	   Before mg_set_websocket_handler has been added, it was primarily useful
	   for noting when a websocket is closing, and used to remove it from any
	   application-maintained list of clients.
	   Using this callback for websocket connections is deprecated: Use
	   mg_set_websocket_handler instead.

	   Connection specific data:
	   If memory has been allocated for the connection specific user data
	   (mg_request_info->conn_data, mg_get_user_connection_data),
	   this is the last chance to free it.
	*/
	void (*connection_close)(const struct mg_connection *);

	/* Called when civetweb is about to serve Lua server page, if
	   Lua support is enabled.
	   Parameters:
	     conn: current connection.
	     lua_context: "lua_State *" pointer. */
	void (*init_lua)(const struct mg_connection *conn, void *lua_context);

#if defined(MG_LEGACY_INTERFACE) /* 2016-05-14 */
	/* Called when civetweb has uploaded a file to a temporary directory as a
	   result of mg_upload() call.
	   Note that mg_upload is deprecated. Use mg_handle_form_request instead.
	   Parameters:
	     file_name: full path name to the uploaded file. */
	void (*upload)(struct mg_connection *, const char *file_name);
#endif

	/* Called when civetweb is about to send HTTP error to the client.
	   Implementing this callback allows to create custom error pages.
	   Parameters:
	     conn: current connection.
	     status: HTTP error status code.
	     errmsg: error message text.
	   Return value:
	     1: run civetweb error handler.
	     0: callback already handled the error. */
	int (*http_error)(struct mg_connection *conn,
					  int status,
					  const char *errmsg);

	/* Called after civetweb context has been created, before requests
	   are processed.
	   Parameters:
	     ctx: context handle */
	void (*init_context)(const struct mg_context *ctx);

	/* Called when a new worker thread is initialized.
	   Parameters:
	     ctx: context handle
	     thread_type:
	       0 indicates the master thread
	       1 indicates a worker thread handling client connections
	       2 indicates an internal helper thread (timer thread)
	       */
	void (*init_thread)(const struct mg_context *ctx, int thread_type);

	/* Called when civetweb context is deleted.
	   Parameters:
	     ctx: context handle */
	void (*exit_context)(const struct mg_context *ctx);

	/* Called when initializing a new connection object.
	 * Can be used to initialize the connection specific user data
	 * (mg_request_info->conn_data, mg_get_user_connection_data).
	 * When the callback is called, it is not yet known if a
	 * valid HTTP(S) request will be made.
	 * Parameters:
	 *   conn: not yet fully initialized connection object
	 *   conn_data: output parameter, set to initialize the
	 *              connection specific user data
	 * Return value:
	 *   must be 0
	 *   Otherwise, the result is undefined
	 */
	int (*init_connection)(const struct mg_connection *conn, void **conn_data);
};


/* Start web server.

   Parameters:
     callbacks: mg_callbacks structure with user-defined callbacks.
     options: NULL terminated list of option_name, option_value pairs that
              specify Civetweb configuration parameters.

   Side-effects: on UNIX, ignores SIGCHLD and SIGPIPE signals. If custom
      processing is required for these, signal handlers must be set up
      after calling mg_start().


   Example:
     const char *options[] = {
       "document_root", "/var/www",
       "listening_ports", "80,443s",
       NULL
     };
     struct mg_context *ctx = mg_start(&my_func, NULL, options);

   Refer to https://github.com/civetweb/civetweb/blob/master/docs/UserManual.md
   for the list of valid option and their possible values.

   Return:
     web server context, or NULL on error. */
CIVETWEB_API struct mg_context *mg_start(const struct mg_callbacks *callbacks,
										 void *user_data,
										 const char **configuration_options);



/* Stop the web server.

   Must be called last, when an application wants to stop the web server and
   release all associated resources. This function blocks until all Civetweb
   threads are stopped. Context pointer becomes invalid. */
CIVETWEB_API void mg_stop(struct mg_context *);


#if defined(MG_EXPERIMENTAL_INTERFACES)
/* Add an additional domain to an already running web server.
 *
 * Parameters:
 *   ctx: Context handle of a server started by mg_start.
 *   options: NULL terminated list of option_name, option_value pairs that
 *            specify CivetWeb configuration parameters.
 *
 * Return:
 *   < 0 in case of an error
 *    -1 for a parameter error
 *    -2 invalid options
 *    -3 initializing SSL failed
 *    -4 mandatory domain option missing
 *    -5 duplicate domain
 *    -6 out of memory
 *   > 0 index / handle of a new domain
 */
CIVETWEB_API int mg_start_domain(struct mg_context *ctx,
                                 const char **configuration_options);
#endif


/* mg_request_handler

   Called when a new request comes in.  This callback is URI based
   and configured with mg_set_request_handler().

   Parameters:
      conn: current connection information.
      cbdata: the callback data configured with mg_set_request_handler().
   Returns:
      0: the handler could not handle the request, so fall through.
      1 - 999: the handler processed the request. The return code is
               stored as a HTTP status code for the access log. */
typedef int (*mg_request_handler)(struct mg_connection *conn, void *cbdata);


/* mg_set_request_handler

   Sets or removes a URI mapping for a request handler.
   This function uses mg_lock_context internally.

   URI's are ordered and prefixed URI's are supported. For example,
   consider two URIs: /a/b and /a
           /a   matches /a
           /a/b matches /a/b
           /a/c matches /a

   Parameters:
      ctx: server context
      uri: the URI (exact or pattern) for the handler
      handler: the callback handler to use when the URI is requested.
               If NULL, an already registered handler for this URI will
               be removed.
               The URI used to remove a handler must match exactly the
               one used to register it (not only a pattern match).
      cbdata: the callback data to give to the handler when it is called. */
CIVETWEB_API void mg_set_request_handler(struct mg_context *ctx,
										 const char *uri,
										 mg_request_handler handler,
										 void *cbdata);



/* Callback types for websocket handlers in C/C++.

   mg_websocket_connect_handler
       Is called when the client intends to establish a websocket connection,
       before websocket handshake.
       Return value:
         0: civetweb proceeds with websocket handshake.
         1: connection is closed immediately.

   mg_websocket_ready_handler
       Is called when websocket handshake is successfully completed, and
       connection is ready for data exchange.

   mg_websocket_data_handler
       Is called when a data frame has been received from the client.
       Parameters:
         bits: first byte of the websocket frame, see websocket RFC at
               http://tools.ietf.org/html/rfc6455, section 5.2
         data, data_len: payload, with mask (if any) already applied.
       Return value:
         1: keep this websocket connection open.
         0: close this websocket connection.

   mg_connection_close_handler
       Is called, when the connection is closed.*/
typedef int (*mg_websocket_connect_handler)(const struct mg_connection *,
											void *);
typedef void (*mg_websocket_ready_handler)(struct mg_connection *, void *);
typedef int (*mg_websocket_data_handler)(struct mg_connection *,
										 int,
										 char *,
										 size_t,
										 void *);
typedef void (*mg_websocket_close_handler)(const struct mg_connection *,
										   void *);

/* struct mg_websocket_subprotocols
 *
 * List of accepted subprotocols
 */
struct mg_websocket_subprotocols {
	int nb_subprotocols;
	char **subprotocols;
};

/* struct mg_websocket_subprotocols
 *
 * List of accepted subprotocols
 */
struct mg_websocket_subprotocols {
	int nb_subprotocols;
	char **subprotocols;
};

/* mg_set_websocket_handler

   Set or remove handler functions for websocket connections.
   This function works similar to mg_set_request_handler - see there. */
CIVETWEB_API void
mg_set_websocket_handler(struct mg_context *ctx,
						 const char *uri,
						 mg_websocket_connect_handler connect_handler,
						 mg_websocket_ready_handler ready_handler,
						 mg_websocket_data_handler data_handler,
						 mg_websocket_close_handler close_handler,
						 void *cbdata);

/* mg_set_websocket_handler

   Set or remove handler functions for websocket connections.
   This function works similar to mg_set_request_handler - see there. */
CIVETWEB_API void mg_set_websocket_handler_with_subprotocols(
		struct mg_context *ctx,
		const char *uri,
		struct mg_websocket_subprotocols *subprotocols,
		mg_websocket_connect_handler connect_handler,
		mg_websocket_ready_handler ready_handler,
		mg_websocket_data_handler data_handler,
		mg_websocket_close_handler close_handler,
		void *cbdata);


/* mg_authorization_handler

   Callback function definition for mg_set_auth_handler

   Parameters:
      conn: current connection information.
      cbdata: the callback data configured with mg_set_request_handler().
   Returns:
      0: access denied
      1: access granted
 */
typedef int (*mg_authorization_handler)(struct mg_connection *conn,
										void *cbdata);


/* mg_set_auth_handler

   Sets or removes a URI mapping for an authorization handler.
   This function works similar to mg_set_request_handler - see there. */
CIVETWEB_API void mg_set_auth_handler(struct mg_context *ctx,
									  const char *uri,
									  mg_authorization_handler handler,
									  void *cbdata);


/* mg_set_websocket_handler

   Set or remove handler functions for websocket connections.
   This function works similar to mg_set_request_handler - see there. */
CIVETWEB_API void mg_set_websocket_handler_with_subprotocols(
    struct mg_context *ctx,
    const char *uri,
    struct mg_websocket_subprotocols *subprotocols,
    mg_websocket_connect_handler connect_handler,
    mg_websocket_ready_handler ready_handler,
    mg_websocket_data_handler data_handler,
    mg_websocket_close_handler close_handler,
    void *cbdata);


/* mg_authorization_handler

   Callback function definition for mg_set_auth_handler

   Parameters:
      conn: current connection information.
      cbdata: the callback data configured with mg_set_request_handler().
   Returns:
      0: access denied
      1: access granted
 */
typedef int (*mg_authorization_handler)(struct mg_connection *conn,
                                        void *cbdata);


/* mg_set_auth_handler

   Sets or removes a URI mapping for an authorization handler.
   This function works similar to mg_set_request_handler - see there. */
CIVETWEB_API void mg_set_auth_handler(struct mg_context *ctx,
                                      const char *uri,
                                      mg_authorization_handler handler,
                                      void *cbdata);


/* Get the value of particular configuration parameter.
   The value returned is read-only. Civetweb does not allow changing
   configuration at run time.
   If given parameter name is not valid, NULL is returned. For valid
   names, return value is guaranteed to be non-NULL. If parameter is not
   set, zero-length string is returned. */
CIVETWEB_API const char *mg_get_option(const struct mg_context *ctx,
									   const char *name);



/* Get context from connection. */
CIVETWEB_API struct mg_context *
mg_get_context(const struct mg_connection *conn);


/* Get user data passed to mg_start from context. */
CIVETWEB_API void *mg_get_user_data(const struct mg_context *ctx);


/* Set user data for the current connection. */
/* Note: This function is deprecated. Use the init_connection callback
   instead to initialize the user connection data pointer. It is
   reccomended to supply a pointer to some user defined data structure
   as conn_data initializer in init_connection. In case it is required
   to change some data after the init_connection call, store another
   data pointer in the user defined data structure and modify that
   pointer. In either case, after the init_connection callback, only
   calls to mg_get_user_connection_data should be required. */
CIVETWEB_API void mg_set_user_connection_data(struct mg_connection *conn,
											  void *data);



/* Get user data set for the current connection. */
CIVETWEB_API void *
mg_get_user_connection_data(const struct mg_connection *conn);


/* Get a formatted link corresponding to the current request

   Parameters:
      conn: current connection information.
      buf: string buffer (out)
      buflen: length of the string buffer
   Returns:
      <0: error
      >=0: ok */
CIVETWEB_API int
mg_get_request_link(const struct mg_connection *conn, char *buf, size_t buflen);


#if defined(MG_LEGACY_INTERFACE) /* 2014-02-21 */
/* Return array of strings that represent valid configuration options.
   For each option, option name and default value is returned, i.e. the
   number of entries in the array equals to number_of_options x 2.
   Array is NULL terminated. */
/* Deprecated: Use mg_get_valid_options instead. */
CIVETWEB_API const char **mg_get_valid_option_names(void);
#endif


struct mg_option {
	const char *name;
	int type;
	const char *default_value;
};

/* Old nomenclature */
#if defined(MG_LEGACY_INTERFACE) /* 2017-10-05 */
enum {
	CONFIG_TYPE_UNKNOWN = 0x0,
	CONFIG_TYPE_NUMBER = 0x1,
	CONFIG_TYPE_STRING = 0x2,
	CONFIG_TYPE_FILE = 0x3,
	CONFIG_TYPE_DIRECTORY = 0x4,
	CONFIG_TYPE_BOOLEAN = 0x5,
	CONFIG_TYPE_EXT_PATTERN = 0x6,
	CONFIG_TYPE_STRING_LIST = 0x7,
	CONFIG_TYPE_STRING_MULTILINE = 0x8
};
#endif

/* New nomenclature */
enum {
	MG_CONFIG_TYPE_UNKNOWN = 0x0,
	MG_CONFIG_TYPE_NUMBER = 0x1,
	MG_CONFIG_TYPE_STRING = 0x2,
	MG_CONFIG_TYPE_FILE = 0x3,
	MG_CONFIG_TYPE_DIRECTORY = 0x4,
	MG_CONFIG_TYPE_BOOLEAN = 0x5,
	MG_CONFIG_TYPE_EXT_PATTERN = 0x6,
	MG_CONFIG_TYPE_STRING_LIST = 0x7,
	MG_CONFIG_TYPE_STRING_MULTILINE = 0x8,
	MG_CONFIG_TYPE_YES_NO_OPTIONAL = 0x9
};

/* Return array of struct mg_option, representing all valid configuration
   options of civetweb.c.
   The array is terminated by a NULL name option. */
CIVETWEB_API const struct mg_option *mg_get_valid_options(void);


struct mg_server_ports {
	int protocol;    /* 1 = IPv4, 2 = IPv6, 3 = both */
	int port;        /* port number */
	int is_ssl;      /* https port: 0 = no, 1 = yes */
	int is_redirect; /* redirect all requests: 0 = no, 1 = yes */
	int _reserved1;
	int _reserved2;
	int _reserved3;
	int _reserved4;
};


/* Get the list of ports that civetweb is listening on.
   The parameter size is the size of the ports array in elements.
   The caller is responsibility to allocate the required memory.
   This function returns the number of struct mg_server_ports elements
   filled in, or <0 in case of an error. */
CIVETWEB_API int mg_get_server_ports(const struct mg_context *ctx,
									 int size,
									 struct mg_server_ports *ports);


#if defined(MG_LEGACY_INTERFACE) /* 2017-04-02 */
/* Deprecated: Use mg_get_server_ports instead. */
CIVETWEB_API size_t mg_get_ports(const struct mg_context *ctx,
                                 size_t size,
                                 int *ports,
                                 int *ssl);
#endif


/* Add, edit or delete the entry in the passwords file.
 *
 * This function allows an application to manipulate .htpasswd files on the
 * fly by adding, deleting and changing user records. This is one of the
 * several ways of implementing authentication on the server side. For another,
 * cookie-based way please refer to the examples/chat in the source tree.
 *
 * Parameter:
 *   passwords_file_name: Path and name of a file storing multiple passwords
 *   realm: HTTP authentication realm (authentication domain) name
 *   user: User name
 *   password:
 *     If password is not NULL, entry modified or added.
 *     If password is NULL, entry is deleted.
 *
 *  Return:
 *    1 on success, 0 on error.
 */
CIVETWEB_API int mg_modify_passwords_file(const char *passwords_file_name,
										  const char *realm,
										  const char *user,
										  const char *password);


/* Return information associated with the request.
 * Use this function to implement a server and get data about a request
 * from a HTTP/HTTPS client.
 * Note: Before CivetWeb 1.10, this function could be used to read
 * a response from a server, when implementing a client, although the
 * values were never returned in appropriate mg_request_info elements.
 * It is strongly advised to use mg_get_response_info for clients.
 */
CIVETWEB_API const struct mg_request_info *
mg_get_request_info(const struct mg_connection *);


/* Return information associated with a HTTP/HTTPS response.
 * Use this function in a client, to check the response from
 * the server. */
CIVETWEB_API const struct mg_response_info *
mg_get_response_info(const struct mg_connection *);


/* Send data to the client.
   Return:
    0   when the connection has been closed
    -1  on error
    >0  number of bytes written on success */
CIVETWEB_API int mg_write(struct mg_connection *, const void *buf, size_t len);


/* Send data to a websocket client wrapped in a websocket frame.  Uses
   mg_lock_connection to ensure that the transmission is not interrupted,
   i.e., when the application is proactively communicating and responding to
   a request simultaneously.

   Send data to a websocket client wrapped in a websocket frame.
   This function is available when civetweb is compiled with -DUSE_WEBSOCKET

   Return:
    0   when the connection has been closed
    -1  on error
    >0  number of bytes written on success */
CIVETWEB_API int mg_websocket_write(struct mg_connection *conn,
									int opcode,
									const char *data,
									size_t data_len);


/* Send data to a websocket server wrapped in a masked websocket frame.  Uses
   mg_lock_connection to ensure that the transmission is not interrupted,
   i.e., when the application is proactively communicating and responding to
   a request simultaneously.

   Send data to a websocket server wrapped in a masked websocket frame.
   This function is available when civetweb is compiled with -DUSE_WEBSOCKET

   Return:
    0   when the connection has been closed
    -1  on error
    >0  number of bytes written on success */
CIVETWEB_API int mg_websocket_client_write(struct mg_connection *conn,
										   int opcode,
										   const char *data,
										   size_t data_len);



/* Send data to a websocket server wrapped in a masked websocket frame.  Uses
   mg_lock_connection to ensure that the transmission is not interrupted,
   i.e., when the application is proactively communicating and responding to
   a request simultaneously.

   Send data to a websocket server wrapped in a masked websocket frame.
   This function is available when civetweb is compiled with -DUSE_WEBSOCKET

   Return:
    0   when the connection has been closed
    -1  on error
    >0  number of bytes written on success */
CIVETWEB_API int mg_websocket_client_write(struct mg_connection *conn,
                                           int opcode,
                                           const char *data,
                                           size_t data_len);


/* Blocks until unique access is obtained to this connection. Intended for use
   with websockets only.
   Invoke this before mg_write or mg_printf when communicating with a
   websocket if your code has server-initiated communication as well as
   communication in direct response to a message. */
CIVETWEB_API void mg_lock_connection(struct mg_connection *conn);
CIVETWEB_API void mg_unlock_connection(struct mg_connection *conn);


#if defined(MG_LEGACY_INTERFACE) /* 2014-06-21 */
#define mg_lock mg_lock_connection
#define mg_unlock mg_unlock_connection
#endif


/* Lock server context.  This lock may be used to protect resources
   that are shared between different connection/worker threads. */
CIVETWEB_API void mg_lock_context(struct mg_context *ctx);
CIVETWEB_API void mg_unlock_context(struct mg_context *ctx);


/* Opcodes, from http://tools.ietf.org/html/rfc6455 */
#if defined(MG_LEGACY_INTERFACE) /* 2017-10-05 */
enum {
	WEBSOCKET_OPCODE_CONTINUATION = 0x0,
	WEBSOCKET_OPCODE_TEXT = 0x1,
	WEBSOCKET_OPCODE_BINARY = 0x2,
	WEBSOCKET_OPCODE_CONNECTION_CLOSE = 0x8,
	WEBSOCKET_OPCODE_PING = 0x9,
	WEBSOCKET_OPCODE_PONG = 0xa
};
#endif

/* New nomenclature */
enum {
	MG_WEBSOCKET_OPCODE_CONTINUATION = 0x0,
	MG_WEBSOCKET_OPCODE_TEXT = 0x1,
	MG_WEBSOCKET_OPCODE_BINARY = 0x2,
	MG_WEBSOCKET_OPCODE_CONNECTION_CLOSE = 0x8,
	MG_WEBSOCKET_OPCODE_PING = 0x9,
	MG_WEBSOCKET_OPCODE_PONG = 0xa
};

/* Macros for enabling compiler-specific checks for printf-like arguments. */
#undef PRINTF_FORMAT_STRING
#if defined(_MSC_VER) && _MSC_VER >= 1400
#include <sal.h>
#if defined(_MSC_VER) && _MSC_VER > 1400
#define PRINTF_FORMAT_STRING(s) _Printf_format_string_ s
#else
#define PRINTF_FORMAT_STRING(s) __format_string s
#endif
#else
#define PRINTF_FORMAT_STRING(s) s
#endif

#ifdef __GNUC__
#define PRINTF_ARGS(x, y) __attribute__((format(printf, x, y)))
#else
#define PRINTF_ARGS(x, y)
#endif


/* Send data to the client using printf() semantics.
   Works exactly like mg_write(), but allows to do message formatting. */
CIVETWEB_API int mg_printf(struct mg_connection *,
						   PRINTF_FORMAT_STRING(const char *fmt),
						   ...) PRINTF_ARGS(2, 3);


/* Send a part of the message body, if chunked transfer encoding is set.
 * Only use this function after sending a complete HTTP request or response
 * header with "Transfer-Encoding: chunked" set. */
CIVETWEB_API int mg_send_chunk(struct mg_connection *conn,
							   const char *chunk,
							   unsigned int chunk_len);


/* Send contents of the entire file together with HTTP headers.
 * Parameters:
 *   conn: Current connection information.
 *   path: Full path to the file to send.
 * This function has been superseded by mg_send_mime_file
 */
CIVETWEB_API void mg_send_file(struct mg_connection *conn, const char *path);


/* Send contents of the file without HTTP headers.
 * The code must send a valid HTTP response header before using this function.
 *
 * Parameters:
 *   conn: Current connection information.
 *   path: Full path to the file to send.
 *
 * Return:
 *   < 0   Error
 */
CIVETWEB_API int mg_send_file_body(struct mg_connection *conn,
								   const char *path);


/* Send HTTP error reply. */
CIVETWEB_API int mg_send_http_error(struct mg_connection *conn,
                                    int status_code,
                                    PRINTF_FORMAT_STRING(const char *fmt),
                                    ...) PRINTF_ARGS(3, 4);


/* Send "HTTP 200 OK" response header.
 * response body.
 * Parameters:
 *   conn: Current connection handle.
 *   mime_type: Set Content-Type for the following content.
 *   content_length: Size of the following content, if content_length >= 0.
 *                   Will set transfer-encoding to chunked, if set to -1.
 * Return:
 *   < 0   Error
 */
CIVETWEB_API int mg_send_http_ok(struct mg_connection *conn,
								 const char *mime_type,
								 long long content_length);


/* Send "HTTP 30x" redirect response.
