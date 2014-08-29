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
#include "pthread.h"
#include "postmaster/postmaster.h"
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

#define MAXLISTEN 64
struct evhttp_bound_socket *listen_handles[MAXLISTEN];

static void
restgres_http_cb(struct evhttp_request *req, void *arg);

const char *path_starts_with(const char *name, const char *path);

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
	while(*name && *path && *name == *path)
	{
		name++;
		path++;
	}

	/* Matched if we reached the end of both strings, or the end of name and a '/' in path */
	if (*name == 0 && (*path == '/' || *path == 0))
		return path;
	return NULL;
}

static void
send_server_meta(struct evhttp_request *req)
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
		send_server_meta(req);
		return;
	}
}

static void
handle_request(struct evhttp_request *req, struct evhttp_uri* uri)
{
	const char *path;

	SetCurrentStatementStartTimestamp();
	StartTransactionCommand();
	PushActiveSnapshot(GetTransactionSnapshot());

	path = evhttp_uri_get_path(uri);
	if(!path || *path == 0 || strcmp("/", path) == 0)
	{
		resource_root(req);
	}
	else
	{
		evhttp_send_error(req, 404, "Not found");
	}

	PopActiveSnapshot();
	CommitTransactionCommand();
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

}

static void
restgres_main(Datum main_arg)
{

	struct event_base 	*base;

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
