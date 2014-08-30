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
#include "tcop/utility.h"
#include "libpq/libpq.h"
#include "postmaster/postmaster.h"
#include "catalog/pg_database.h"

#include "evsql.h"

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

struct evsql_conn {
	const char *conninfo;
	struct evsql *evsql;
};

// List of evsql instances, we need a separate one for each set of credentials
// since once connected we cannot change the credentials.
static List *evsql_list = NIL;

#define MAXLISTEN 64
struct evhttp_bound_socket *listen_handles[MAXLISTEN];

static void restgres_http_cb(struct evhttp_request *req, void *arg);
static struct evsql *evsql_for_request(struct evhttp_request *req, const char *database);

const char *path_starts_with(const char *name, const char *path);

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
	for(a = input; *a; a++, b++)
	{
		if(*a == q)
		{
			*b = '\\';
			b++;
		}
		*b = *a;
	}
	return output;
}

static
const char *_escape_single_quotes(const char *input)
{
	return _escape_quotes(input, '\'');
}

static
const char *_escape_double_quotes(const char *input)
{
	return _escape_quotes(input, '"');
}

static struct evsql *evsql_for_params(struct event_base *base, const char *user, const char *password, const char *client_encoding, const char *database)
{
	struct evsql *evsql = NULL;
	const char *database_hdr;
	struct evsql_conn *conn;
	char *conninfo=NULL;
	ListCell   *l;
	StringInfoData str;

	user = _escape_single_quotes(user);
	password = _escape_single_quotes(password);
	client_encoding = _escape_single_quotes(client_encoding);
	database = _escape_single_quotes(database);

	if(!(database_hdr && *database_hdr)) database_hdr = user;

	initStringInfo(&str);
	if(user) appendStringInfo(&str, "user='%s' password='%s' ", user, password?password:"");
	appendStringInfo(&str, "client_encoding='%s' database='%s'", client_encoding, database_hdr);
	conninfo = str.data;

	foreach(l, evsql_list)
	{
		conn = lfirst(l);
		if(strcmp(conn->conninfo, conninfo) == 0)
		{
			conninfo = NULL;
			evsql = conn->evsql;
			break;
		}

	}

	if (!evsql)
	{
		conn = calloc(1, sizeof(*conn));
		conn->evsql = evsql = evsql_new_pq(base, conninfo, NULL, NULL);
		conn->conninfo = strdup(conninfo); // Have to strdup since conninfo will be freed automatically
		lcons(conn, evsql_list);
	}

	pfree(str.data);

	return evsql;
}


/* Get or open a new connection for the given request */
static struct evsql *evsql_for_request(struct evhttp_request *req, const char *database)
{
	struct evkeyvalq *headers;
	const char *user;
	const char *password;
	const char *client_encoding;
	struct event_base *base;

	headers = evhttp_request_get_input_headers(req);
	user = _escape_single_quotes(evhttp_find_header(headers, "x-postgresql-user"));
	password = _escape_single_quotes(evhttp_find_header(headers, "x-postgresql-password"));
	client_encoding = "utf8";
	base = evhttp_connection_get_base(evhttp_request_get_connection(req));
	return evsql_for_params(base, user, password, client_encoding, database);
}

static bool is_logged_in(struct evhttp_request *req, const char *database)
{
	struct evkeyvalq *headers;
	const char *password;
	Port port = {0};
	struct evhttp_connection *conn;
	const struct sockaddr *remote_addr;
	char *client_address;
	ev_uint16_t client_port;

	headers = evhttp_request_get_input_headers(req);
	port.user_name = (char *)evhttp_find_header(headers, "x-postgresql-user");
	password = evhttp_find_header(headers, "x-postgresql-password");

	conn = evhttp_request_get_connection(req);

	remote_addr = evhttp_connection_get_addr(conn);
	if(remote_addr)
		memcpy(&port.raddr.addr, remote_addr, sizeof port.raddr.addr);

	evhttp_connection_get_peer(conn, &port.remote_host, &client_port);

	hba_getauthmethod(&port);

	return STATUS_OK == md5_crypt_verify(&port, port.user_name, password);
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
const char *path_starts_with(const char *name, const char *path)
{
	while(*name == *path)
	{
		if(*path == 0)
			return path;
		name++;
		path++;
		if(*name == 0 && *path == '/')
			return path+1;
	}

	/* Matched if we reached the end of both strings, or the end of name and a '/' in path */
	if (*name == *path)
		return path;
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

	SetCurrentStatementStartTimestamp();
	StartTransactionCommand();
	SPI_connect();
	PushActiveSnapshot(GetTransactionSnapshot());
	pgstat_report_activity(STATE_RUNNING, "listing databases");

	buf = evbuffer_new();
	evbuffer_add_printf(buf, "{ \"databases\":\n    [");

	ret = SPI_execute("SELECT datname FROM pg_database WHERE datistemplate = false;", true, 0);
	if (ret != SPI_OK_SELECT)
		elog(FATAL, "SPI_execute failed: error code %d", ret);
	char *nl = "";
	for(int i=0; i < SPI_processed; i++)
	{
		spi_tuptable = SPI_tuptable;
		spi_tupdesc = spi_tuptable->tupdesc;
		spi_tuple = SPI_tuptable->vals[i];
		datname = SPI_getvalue(spi_tuple, spi_tupdesc, 1);
		elog(LOG, "Found database '%s'", datname);
		evbuffer_add_printf(buf, "%s{ \"name\":\"%s\" }", nl, _escape_double_quotes(datname));
		nl = ",\n    ";
	}

	PopActiveSnapshot();
	CommitTransactionCommand();
	pgstat_report_activity(STATE_IDLE, NULL);


	evbuffer_add_printf(buf, "%s]\n}\n", nl);
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
	switch (evhttp_request_get_command(req)) {
	case EVHTTP_REQ_GET:
		resource_databases_GET(req);
		return;
	default:
		evhttp_send_error(req, 405, "Method not supported");
		return;
	}
}

static void
handle_request(struct evhttp_request *req, struct evhttp_uri* uri)
{
	const char *path;

	path = evhttp_uri_get_path(uri);
	if(!path || *path == 0 || strcmp("/", path) == 0)
		resource_root(req);
	else if(strcmp("/databases", path) == 0)
		resource_databases(req);
	else {
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
	evhttp_send_reply(req, 200, "OK", NULL);

	// Is this the right thing to do here?
	MemoryContextReset(CurrentMemoryContext);

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
	// pqsignal(SIGHUP, restgres_sighup);
	// pqsignal(SIGTERM, restgres_sigterm);
	evsignal_new(base, SIGHUP, (event_callback_fn)restgres_sighup, (void *)base);
	evsignal_new(base, SIGTERM, (event_callback_fn)restgres_sigterm, (void *)base);

	event_new(base, postmaster_alive_fds[POSTMASTER_FD_WATCH], EV_READ, postmaster_death_cb, (void *)base);

	/* We're now ready to receive signals */
	BackgroundWorkerUnblockSignals();

	initialize_restgres(base);

	elog(LOG, "RESTgres initialized, port %d, listen_addresses = \"%s\"", restgres_listen_port, restgres_listen_addresses);

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
							"Duration between each check (in seconds).",
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

	/*
	 * Now fill in worker-specific data, and do the actual registrations.
	 */
	strncpy(worker.bgw_name, "RESTgres worker", BGW_MAXLEN);

	RegisterBackgroundWorker(&worker);
}
