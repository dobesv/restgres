/* -------------------------------------------------------------------------
 *
 * restgres.c
 *		Sample background worker code that demonstrates various coding
 *		patterns: establishing a database connection; starting and committing
 *		transactions; using GUC variables, and heeding SIGHUP to reread
 *		the configuration file; reporting to pg_stat_activity; using the
 *		process latch to sleep and exit in case of postmaster death.
 *
 * This code connects to a database, creates a schema and table, and summarizes
 * the numbers contained therein.  To see it working, insert an initial value
 * with "total" type and some initial value; then insert some other rows with
 * "delta" type.  Delta rows will be deleted by this worker and their values
 * aggregated into the total.
 *
 * Copyright (C) 2013, PostgreSQL Global Development Group
 *
 * IDENTIFICATION
 *		contrib/restgres/restgres.c
 *
 * -------------------------------------------------------------------------
 */
#define sigjmp_buf jmp_buf
#include "setjmp.h"
#include "unistd.h"

#include "postgres.h"

/* These are always necessary for a bgworker */
#include "miscadmin.h"
#include "postmaster/bgworker.h"
#include "storage/ipc.h"
#include "storage/latch.h"
#include "storage/lwlock.h"
#include "storage/proc.h"
#include "storage/shmem.h"

/* these headers are used by this particular worker's code */
#include "access/xact.h"
#include "executor/spi.h"
#include "fmgr.h"
#include "lib/stringinfo.h"
#include "pgstat.h"
#include "utils/builtins.h"
#include "utils/snapmgr.h"
#include "utils/memutils.h"
#include "tcop/utility.h"
#include "libpq/libpq.h"
#include "libpq/crypt.h"
#include "libpq/ip.h"
#include "postmaster/postmaster.h"
#include "catalog/pg_database.h"

#include <event2/event.h>
#include <event2/http.h>
#include <event2/buffer.h>
#include <event2/util.h>
#include <event2/keyvalq_struct.h>

PG_MODULE_MAGIC;

void		_PG_init(void);

/* flags set by signal handlers */
static volatile sig_atomic_t got_sighup = false;
static volatile sig_atomic_t got_sigterm = false;
static volatile sig_atomic_t got_pgdeath = false;

/* GUC variables */
static int restgres_listen_port = 0;
static char *restgres_listen_addresses = 0;
static int restgres_max_connections = 0;

#define MAXLISTEN 64
struct evhttp_bound_socket *listen_handles[MAXLISTEN];

static void restgres_http_cb(struct evhttp_request *req, void *arg);

const char *remove_prefix(const char *name, const char *path);

void
escape_json(StringInfo buf, const char *str);

/*
 * Escape quotes in the string, if there are any.  If not, returns the original string.  Any
 * new string returned is allocated using palloc, which means it will be freed at the end of the request
 * processing.
 */
static
const char *_escape_quotes(const char *input, char q)
{
	int len = 1;
	int quotes = 0;
	char *output;
	const char *a;
	char *b;

	if(input == NULL)
		return NULL;
	for(const char *p=input; *p; p++)
	{
		if(*p == q) len++;
		len ++;
		quotes ++;
	}

	if(quotes == 0)
		return input;

	b = output = palloc(len);
	for(a = input; *a; a++)
	{
		if(*a == q || *a == '\\')
		{
			*b = '\\';
			b++;
		}
		*b = *a;
		b++;
	}
	*b = 0;
	return output;
}

/*
 * Produce a JSON string literal, properly escaping characters in the text.
 */
void
escape_json(StringInfo buf, const char *str)
{
	const char *p;

	appendStringInfoCharMacro(buf, '\"');
	for (p = str; *p; p++)
	{
		switch (*p)
		{
			case '\b':
				appendStringInfoString(buf, "\\b");
				break;
			case '\f':
				appendStringInfoString(buf, "\\f");
				break;
			case '\n':
				appendStringInfoString(buf, "\\n");
				break;
			case '\r':
				appendStringInfoString(buf, "\\r");
				break;
			case '\t':
				appendStringInfoString(buf, "\\t");
				break;
			case '"':
				appendStringInfoString(buf, "\\\"");
				break;
			case '\\':

				/*
				 * Unicode escapes are passed through as is. There is no
				 * requirement that they denote a valid character in the
				 * server encoding - indeed that is a big part of their
				 * usefulness.
				 *
				 * All we require is that they consist of \uXXXX where the Xs
				 * are hexadecimal digits. It is the responsibility of the
				 * caller of, say, to_json() to make sure that the unicode
				 * escape is valid.
				 *
				 * In the case of a jsonb string value being escaped, the only
				 * unicode escape that should be present is \u0000, all the
				 * other unicode escapes will have been resolved.
				 */
				if (p[1] == 'u' &&
					isxdigit((unsigned char) p[2]) &&
					isxdigit((unsigned char) p[3]) &&
					isxdigit((unsigned char) p[4]) &&
					isxdigit((unsigned char) p[5]))
					appendStringInfoCharMacro(buf, *p);
				else
					appendStringInfoString(buf, "\\\\");
				break;
			default:
				if ((unsigned char) *p < ' ')
					appendStringInfo(buf, "\\u%04x", (int) *p);
				else
					appendStringInfoCharMacro(buf, *p);
				break;
		}
	}
	appendStringInfoCharMacro(buf, '\"');
}


//static
//const char *_escape_single_quotes(const char *input)
//{
//	return _escape_quotes(input, '\'');
//}

static
const char *_escape_double_quotes(const char *input)
{
	return _escape_quotes(input, '"');
}

/**
 * Add a null-terminated string to the buffer.
 */
static void evbuffer_add_cstring(struct evbuffer *buf, const char *str) {
	evbuffer_add(buf, str, strlen(str));
}



static bool is_anonymous(struct evhttp_request *req)
{
	struct evkeyvalq *headers;
	const char *user_name;
	headers = evhttp_request_get_input_headers(req);
	user_name = evhttp_find_header(headers, "x-postgresql-user");
	return user_name == NULL;
}
static bool is_logged_in(struct evhttp_request *req, const char *database)
{
	struct evkeyvalq *headers;
	const char *password;
	Port _port = {0};
	Port *port = &_port;
	struct evhttp_connection *conn;
	ev_uint16_t client_port;
	int sockaddrlen = sizeof _port.raddr.addr;
	int rc = STATUS_ERROR;
	char *logdetail = "auth failed";

	headers = evhttp_request_get_input_headers(req);
	port->user_name = (char *)evhttp_find_header(headers, "x-postgresql-user");
	password = evhttp_find_header(headers, "x-postgresql-password");
	conn = evhttp_request_get_connection(req);
	evhttp_connection_get_peer(conn, &_port.remote_host, &client_port);
	evutil_parse_sockaddr_port(_port.remote_host, (struct sockaddr *)&_port.raddr.addr, &sockaddrlen);

	// Need to follow the logic in auth.c#ClientAuthentication
	hba_getauthmethod(port);
	if(!_port.hba)
	{
		elog(LOG, "No matching line in hba.conf for this connection, cannot authenticate.");
		return false; // No matching HBA line found
	}

	/*
	 * Now proceed to do the actual authentication check
	 */
	switch (port->hba->auth_method)
	{
		case uaReject:

			/*
			 * An explicit "reject" entry in pg_hba.conf.  This report exposes
			 * the fact that there's an explicit reject entry, which is
			 * perhaps not so desirable from a security standpoint; but the
			 * message for an implicit reject could confuse the DBA a lot when
			 * the true situation is a match to an explicit reject.  And we
			 * don't want to change the message for an implicit reject.  As
			 * noted below, the additional information shown here doesn't
			 * expose anything not known to an attacker.
			 */
			{
				char		hostinfo[NI_MAXHOST];

				pg_getnameinfo_all(&port->raddr.addr, port->raddr.salen,
								   hostinfo, sizeof(hostinfo),
								   NULL, 0,
								   NI_NUMERICHOST);

#ifdef USE_SSL
				ereport(FATAL,
				   (errcode(ERRCODE_INVALID_AUTHORIZATION_SPECIFICATION),
					errmsg("pg_hba.conf rejects connection for host \"%s\", user \"%s\", database \"%s\", %s",
						   hostinfo, port->user_name,
						   port->database_name,
						   port->ssl ? _("SSL on") : _("SSL off"))));
#else
				ereport(FATAL,
				   (errcode(ERRCODE_INVALID_AUTHORIZATION_SPECIFICATION),
					errmsg("pg_hba.conf rejects connection for host \"%s\", user \"%s\", database \"%s\"",
						   hostinfo, port->user_name,
						   port->database_name)));
#endif
				break;
			}

		case uaImplicitReject:

			/*
			 * No matching entry, so tell the user we fell through.
			 *
			 * NOTE: the extra info reported here is not a security breach,
			 * because all that info is known at the frontend and must be
			 * assumed known to bad guys.  We're merely helping out the less
			 * clueful good guys.
			 */
			{
				char		hostinfo[NI_MAXHOST];

				pg_getnameinfo_all(&port->raddr.addr, port->raddr.salen,
								   hostinfo, sizeof(hostinfo),
								   NULL, 0,
								   NI_NUMERICHOST);

#define HOSTNAME_LOOKUP_DETAIL(port) \
				(port->remote_hostname ? \
				 (port->remote_hostname_resolv == +1 ? \
				  errdetail_log("Client IP address resolved to \"%s\", forward lookup matches.", \
								port->remote_hostname) : \
				  port->remote_hostname_resolv == 0 ? \
				  errdetail_log("Client IP address resolved to \"%s\", forward lookup not checked.", \
								port->remote_hostname) : \
				  port->remote_hostname_resolv == -1 ? \
				  errdetail_log("Client IP address resolved to \"%s\", forward lookup does not match.", \
								port->remote_hostname) : \
				  port->remote_hostname_resolv == -2 ? \
				  errdetail_log("Could not translate client host name \"%s\" to IP address: %s.", \
								port->remote_hostname, \
								gai_strerror(port->remote_hostname_errcode)) : \
				  0) \
				 : (port->remote_hostname_resolv == -2 ? \
					errdetail_log("Could not resolve client IP address to a host name: %s.", \
								  gai_strerror(port->remote_hostname_errcode)) : \
					0))

#ifdef USE_SSL
				ereport(FATAL,
				   (errcode(ERRCODE_INVALID_AUTHORIZATION_SPECIFICATION),
					errmsg("no pg_hba.conf entry for host \"%s\", user \"%s\", database \"%s\", %s",
						   hostinfo, port->user_name,
						   port->database_name,
						   port->ssl ? _("SSL on") : _("SSL off")),
					HOSTNAME_LOOKUP_DETAIL(port)));
#else
				ereport(FATAL,
				   (errcode(ERRCODE_INVALID_AUTHORIZATION_SPECIFICATION),
					errmsg("no pg_hba.conf entry for host \"%s\", user \"%s\", database \"%s\"",
						   hostinfo, port->user_name,
						   port->database_name),
					HOSTNAME_LOOKUP_DETAIL(port)));
#endif
				break;
			}

		default:
		case uaGSS:
		case uaSSPI:
		case uaPeer:
		case uaIdent:
		case uaPAM:
		case uaLDAP:
		case uaCert:
		case uaRADIUS:
			logdetail = "GSS/SSPI/UNIX domain socket/identd/PAM/LDAP/Cert/RADIUS auth support not available via HTTP (yet).";
			rc = STATUS_ERROR;
			break;

		case uaMD5:
//			if (Db_user_namespace)
//				ereport(FATAL,
//						(errcode(ERRCODE_INVALID_AUTHORIZATION_SPECIFICATION),
//						 errmsg("MD5 authentication is not supported when \"db_user_namespace\" is enabled")));
		case uaPassword:
			if(password == NULL || password[0] == 0)
			{
				rc = STATUS_ERROR;
				logdetail = "User did not provide a password";
			}
			else
			{
				rc = md5_crypt_verify(port, port->user_name, (char *)password, &logdetail);
				if(rc != STATUS_OK)
					elog(WARNING, "Password verification failed for user '%s': %s", port->user_name, logdetail?logdetail:"no detail available");
			}
			break;

		case uaTrust:
			rc = STATUS_OK;
			break;
	}

	return rc == STATUS_OK;
}

static bool
require_logged_in(struct evhttp_request *req, const char *database)
{
	if(is_anonymous(req))
	{
		evhttp_send_error(req, 403, "You must log in to view database information");
		return false;
	}
	else if(is_logged_in(req, database))
	{
		return true;
	}
	else
	{
		evhttp_send_error(req, 403, "Bad credentials");
		return false;
	}
}

/*
 * Signal handler for SIGTERM
 *		Set a flag to let the main loop to terminate, and set our latch to wake
 *		it up.
 */
static void
restgres_sigterm(evutil_socket_t s, short what, void *arg)
{
	got_sigterm = true;
	event_base_loopbreak((struct event_base *)arg);
}

/*
 * Signal handler for SIGHUP
 *		Set a flag to tell the main loop to reread the config file, and set
 *		our latch to wake it up.
 */
static void
restgres_sighup(evutil_socket_t s, short what, void *arg)
{
	got_sighup = true;
	event_base_loopbreak((struct event_base *)arg);
}

static void
postmaster_death_cb(evutil_socket_t s, short what, void *arg)
{
	got_pgdeath = true;
	event_base_loopbreak((struct event_base *)arg);
}

static void
listen_for_connections(struct evhttp *http)
{
	char	   *rawstring;
	List	   *elemlist = NIL;
	ListCell   *l;
	int			success = 0;

	/* Need a modifiable copy of ListenAddresses */
	rawstring = pstrdup(restgres_listen_addresses);

	/* Parse string into path components */
	if (!SplitIdentifierString(rawstring, '/', &elemlist))
	{
		/* syntax error in list */
		ereport(FATAL,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("invalid list syntax in parameter \"%s\"",
						"listen_addresses")));
	}
	else
	{
		foreach(l, elemlist)
		{
			char	   *curhost = (char *) lfirst(l);
			struct evhttp_bound_socket *handle;

			if (strcmp(curhost, "*") == 0)
				handle = evhttp_bind_socket_with_handle(http, "0.0.0.0", restgres_listen_port);

			else
				handle = evhttp_bind_socket_with_handle(http, curhost, restgres_listen_port);
			if (handle)
			{
				listen_handles[success] = handle;
				success++;
				ereport(LOG, (errmsg("Listening on %s:%d", curhost, restgres_listen_port)));
			}
			else
				ereport(WARNING,
						(errmsg("could not create listen socket for \"%s\"", curhost)));
		}
	}
	if (!success && elemlist != NIL)
		ereport(FATAL,
				(errmsg("could not create any TCP/IP sockets")));

	list_free(elemlist);
	pfree(rawstring);

}

/*
 * Initialize workspace for a worker process: create the schema if it doesn't
 * already exist.
 */
static void
initialize_restgres(struct event_base *base)
{
	struct evhttp 	*http;

	/* Create a new evhttp object to handle requests. */
	http = evhttp_new(base);
	if (!http)
	{
		elog(ERROR, "Couldn't create evhttp");
		return;
	}

	/* Set callback for incoming HTTP requests*/
	evhttp_set_gencb(http, restgres_http_cb, (void *)http);

	listen_for_connections(http);

	/* Connect to our database */
	BackgroundWorkerInitializeConnection("postgres", NULL);
}

/* Check whether the input starts with the given path component; returns the remainder of the string if so */
const char *remove_prefix(const char *prefix, const char *input)
{
	int len = strlen(prefix);
	if(strncmp(prefix, input, len) == 0)
		return input + len;
	return NULL;
}



static void
resource_root_GET(struct evhttp_request *req)
{
	struct evbuffer *databuf;
	databuf = evbuffer_new();
	evbuffer_add_printf(databuf,
			"{\n"
			"    \"version\":\"" PG_VERSION "\"\n"
			"    \"version_num\":%d\n"
			"}\n", PG_VERSION_NUM);
	evhttp_add_header(evhttp_request_get_output_headers(req),
	    "Server", "RESTgres");
	evhttp_add_header(evhttp_request_get_output_headers(req),
	    "Content-Type", "text/plain");
	evhttp_send_reply(req, 200, "OK", databuf);
	evbuffer_free(databuf);
}

static void
resource_root(struct evhttp_request *req)
{
	switch (evhttp_request_get_command(req)) {
	case EVHTTP_REQ_GET:
		resource_root_GET(req);
		return;
	default:
		evhttp_send_error(req, 405, "Method not supported");
		return;
	}
}

static void
resource_databases_GET_json(struct evhttp_request *req)
{
	int			ret;
	HeapTuple	spi_tuple;
	SPITupleTable *spi_tuptable = SPI_tuptable;
	TupleDesc	spi_tupdesc = spi_tuptable->tupdesc;
	const char *datname;
	struct evbuffer *buf;

	buf = evbuffer_new();
	evbuffer_add_printf(buf, "{\n  \"databases\": ");

	ret = SPI_execute("SELECT datname FROM pg_database WHERE datistemplate = false;", true, 0);
	if (ret != SPI_OK_SELECT)
		elog(FATAL, "SPI_execute failed: error code %d", ret);
	if(SPI_processed == 0)
		evbuffer_add_cstring(buf, "[]\n");
	else
	{
		evbuffer_add_cstring(buf, "[");
		for(int i=0; i < SPI_processed; i++)
		{
			StringInfo name_buf = makeStringInfo();
			spi_tuptable = SPI_tuptable;
			spi_tupdesc = spi_tuptable->tupdesc;
			spi_tuple = SPI_tuptable->vals[i];
			datname = SPI_getvalue(spi_tuple, spi_tupdesc, 1);
			elog(LOG, "Found database '%s'", datname);
			escape_json(name_buf, datname);
			evbuffer_add_cstring(buf, i==0?"\n    ":",\n    ");
			evbuffer_add_cstring(buf, "{ \"name\":");
			evbuffer_add_cstring(buf, name_buf->data);
			evbuffer_add_cstring(buf, " }");
		}

		evbuffer_add_cstring(buf, "\n  ]\n");
	}
	evbuffer_add_cstring(buf, "}\n");
	evhttp_add_header(evhttp_request_get_output_headers(req),
	    "Server", "RESTgres");
	evhttp_add_header(evhttp_request_get_output_headers(req),
	    "Content-Type", "application/json; charset=utf8");
	evhttp_send_reply(req, 200, "OK", buf);
	evbuffer_free(buf);

}

static void
resource_databases_GET(struct evhttp_request *req)
{
	// TODO Content-type negotiation
	resource_databases_GET_json(req);
}

static void
resource_databases(struct evhttp_request *req)
{
	if(require_logged_in(req, "postgres"))
	{
		switch (evhttp_request_get_command(req))
		{
		case EVHTTP_REQ_GET:
			resource_databases_GET(req);
			return;
		default:
			evhttp_send_error(req, 405, "Method not supported");
			return;
		}
	}
}

static void
resource_database_GET(struct evhttp_request *req, const char *database)
{
	evhttp_send_error(req, 405, "Database metadata not implemented yet.");
}

static void
resource_database(struct evhttp_request *req, const char *database)
{
	if(require_logged_in(req, database))
	{
		switch (evhttp_request_get_command(req))
		{
		case EVHTTP_REQ_GET:
			resource_database_GET(req, database);
			return;
		default:
			evhttp_send_error(req, 405, "Method not supported");
			return;
		}
	}
}

static void
handle_request(struct evhttp_request *req, struct evhttp_uri* uri)
{
	const char *path;
	const char *db_start;

	path = evhttp_uri_get_path(uri);
	if(!path || *path == 0 || strcmp("/", path) == 0)
		resource_root(req);
	else if(strcmp("/databases", path) == 0)
	{
		resource_databases(req);
		return;
	}
	else if((db_start = remove_prefix("/databases/", path)) != NULL)
	{
		// Starts with /databases/ ...
		const char *db_start = path + strlen("/databases/");
		const char *db_end = strchr(db_start, '/');
		if(db_end == NULL)
			resource_database(req, db_start);
		else
			evhttp_send_error(req, 404, "Not implemented yet - stuff inside a database");

	}
	else
	{
		elog(LOG, "Path matching failed at the root: '%s'", path);
		evhttp_send_error(req, 404, "Not found");
	}
}
static void
restgres_http_cb(struct evhttp_request *req, void *arg)
{
	const char *cmdtype;
	struct evkeyvalq *headers;
	struct evkeyval *header;
	struct evbuffer *buf;
	struct evhttp_uri* uri;
	MemoryContext oldcontext;
	MemoryContext context;

	context = AllocSetContextCreate(CurrentMemoryContext,
			 "request temporary context",
			 ALLOCSET_DEFAULT_MINSIZE,
			 ALLOCSET_DEFAULT_INITSIZE,
			 ALLOCSET_DEFAULT_MAXSIZE);
	AssertArg(MemoryContextIsValid(context));
	oldcontext = MemoryContextSwitchTo(context);

	SetCurrentStatementStartTimestamp();
	StartTransactionCommand();
	SPI_connect();
	PushActiveSnapshot(GetTransactionSnapshot());
	pgstat_report_activity(STATE_RUNNING, "Handling request");
	switch (evhttp_request_get_command(req)) {
	case EVHTTP_REQ_GET: cmdtype = "GET"; break;
	case EVHTTP_REQ_POST: cmdtype = "POST"; break;
	case EVHTTP_REQ_HEAD: cmdtype = "HEAD"; break;
	case EVHTTP_REQ_PUT: cmdtype = "PUT"; break;
	case EVHTTP_REQ_DELETE: cmdtype = "DELETE"; break;
	case EVHTTP_REQ_OPTIONS: cmdtype = "OPTIONS"; break;
	case EVHTTP_REQ_TRACE: cmdtype = "TRACE"; break;
	case EVHTTP_REQ_CONNECT: cmdtype = "CONNECT"; break;
	case EVHTTP_REQ_PATCH: cmdtype = "PATCH"; break;
	default: cmdtype = "unknown"; break;
	}

	uri = evhttp_uri_parse(evhttp_request_get_uri(req));
	elog(LOG, "Received a %s request for %s; Headers:",
	    cmdtype, evhttp_request_get_uri(req));
	if(!uri)
	{
		evhttp_send_error(req, 400, "Invalid URI");
	}
	else
	{
		handle_request(req, uri);
		evhttp_uri_free(uri);
	}

	headers = evhttp_request_get_input_headers(req);
	for (header = headers->tqh_first; header;
	    header = header->next.tqe_next) {
		elog(LOG, "  %s: %s", header->key, header->value);
	}

	buf = evhttp_request_get_input_buffer(req);
	elog(LOG, "Input data:");
	while (evbuffer_get_length(buf)) {
		int n;
		char cbuf[128];
		n = evbuffer_remove(buf, cbuf, sizeof(cbuf));
		if (n > 0)
			(void) fwrite(cbuf, 1, n, stdout);
	}

	SPI_finish();
	PopActiveSnapshot();
	CommitTransactionCommand();
	pgstat_report_activity(STATE_IDLE, NULL);
	MemoryContextSwitchTo(oldcontext);
	MemoryContextReset(context);
}

static void
restgres_main(Datum main_arg)
{
	static struct event_base 	*base;

	base = event_base_new();
	if (!base)
	{
		elog(ERROR, "Couldn't create event_base");
		proc_exit(1);
		return;
	}

	/* Establish signal handlers before unblocking signals. */
	evsignal_new(base, SIGHUP, (event_callback_fn)restgres_sighup, (void *)base);
	evsignal_new(base, SIGTERM, (event_callback_fn)restgres_sigterm, (void *)base);

	event_new(base, postmaster_alive_fds[POSTMASTER_FD_WATCH], EV_READ, postmaster_death_cb, (void *)base);

	/* We're now ready to receive signals */
	BackgroundWorkerUnblockSignals();

	initialize_restgres(base);

	elog(LOG, "RESTgres initialized, pid %d port %d listen_addresses \"%s\"", getpid(), restgres_listen_port, restgres_listen_addresses);

	event_base_dispatch(base);

	proc_exit(0);
}

/*
 * Entrypoint of this module.
 *
 * We register more than one worker process here, to demonstrate how that can
 * be done.
 */
void
_PG_init(void)
{
	BackgroundWorker worker;

	/* get the configuration */
	DefineCustomIntVariable("restgres.port",
							"Port to listen on (default: any available port)",
							NULL,
							&restgres_listen_port,
							restgres_listen_port,
							0,
							32768,
							PGC_SIGHUP,
							0,
							NULL,
							NULL,
							NULL);
	DefineCustomIntVariable("restgres.max_connections",
							"Maximum number of connections to serve at once (additional connections will have to wait or be rejected)",
							NULL,
							&restgres_max_connections,
							0,
							0,
							INT_MAX,
							PGC_SIGHUP,
							0,
							NULL,
							NULL,
							NULL);
	DefineCustomStringVariable("restgres.listen_addresses",
							"Comma-separated list of databases to make available via HTTP; one worker will be started for each database",
							NULL,
							&restgres_listen_addresses,
							"*",
							PGC_SIGHUP,
							0,
							NULL,
							NULL,
							NULL);

	/* set up common data for all our workers */
	worker.bgw_flags = BGWORKER_SHMEM_ACCESS | BGWORKER_BACKEND_DATABASE_CONNECTION;
	worker.bgw_start_time = BgWorkerStart_RecoveryFinished;
	worker.bgw_restart_time = BGW_DEFAULT_RESTART_INTERVAL;
	worker.bgw_main = restgres_main;
	worker.bgw_notify_pid = 0;

	/*
	 * Now fill in worker-specific data, and do the actual registrations.
	 */
	strncpy(worker.bgw_name, "RESTgres worker", BGW_MAXLEN);

	RegisterBackgroundWorker(&worker);
}
