#define sigjmp_buf jmp_buf
#include "setjmp.h"
#include "unistd.h"

#include "postgres.h"

/* These are always necessary for a bgworker */
#include "miscadmin.h"
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
#include "postmaster/bgworker.h"
#include "catalog/pg_database.h"

#include <event2/event.h>
#include <event2/http.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/util.h>
#include <event2/keyvalq_struct.h>
#include <event2/bufferevent.h>
#include <event2/http_struct.h>

#include <sys/queue.h>

#include "bgwutil.h"
#include "util.h"
#include "backend.h"
#include "master.h"
#include "sendrecvfd.h"

/* GUC variables */
int restgres_listen_port;
char *restgres_listen_addresses;

int restgres_max_connections;
int restgres_max_concurrency;

MemoryContext request_context;

SIMPLEQ_HEAD(queued_requests, restgres_queued_request) queued_requests = SIMPLEQ_HEAD_INITIALIZER(queued_requests);

#define MAXLISTEN 64
struct evhttp_bound_socket *listen_handles[MAXLISTEN];


static void
restgres_http_cb(struct evhttp_request *req, void *arg);
static const char *
check_authenticated(struct evhttp_request *req, const char *dbname);
static void
enqueue_request(const char *dbname, const char *user_name, struct evbuffer *buf, int reply_fd);
static void
terminate_backend(struct restgres_backend* backend);
static void
worker_listener_error_cb(struct evconnlistener *lev, void *arg);

struct restgres_backend *backends = NULL;

/* Number of messages sent to the backend; used as a clock for the LRU reallocation of backends */
static long long int message_counter = 0;



static bool is_anonymous(struct evhttp_request *req)
{
	struct evkeyvalq *headers;
	const char *user_name;
	headers = evhttp_request_get_input_headers(req);
	user_name = evhttp_find_header(headers, "x-postgresql-user");
	return user_name == NULL;
}
static const char *is_logged_in(struct evhttp_request *req, const char *dbname)
{
	struct evkeyvalq *headers;
	const char *password;
	Port _port = { 0 };
	Port *port = &_port;
	struct evhttp_connection *conn;
	ev_uint16_t client_port;
	int sockaddrlen = sizeof _port.raddr.addr;
	int rc = STATUS_ERROR;
	char *logdetail = "auth failed";
	const char *user_name;

	headers = evhttp_request_get_input_headers(req);
	user_name = port->user_name = (char *) evhttp_find_header(headers, "x-postgresql-user");
	if(user_name == NULL)
	{
		logdetail = "No username provided.";
		return false;
	}

	port->database_name = (char *) dbname;

	password = evhttp_find_header(headers, "x-postgresql-password");
	conn = evhttp_request_get_connection(req);
	evhttp_connection_get_peer(conn, &_port.remote_host, &client_port);
	evutil_parse_sockaddr_port(_port.remote_host,
			(struct sockaddr *) &_port.raddr.addr, &sockaddrlen);

	// Need to follow the logic in auth.c#ClientAuthentication
	hba_getauthmethod(port);
	if (!_port.hba)
	{
		elog(LOG,
				"No matching line in hba.conf for this connection, cannot authenticate.");
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
		char hostinfo[NI_MAXHOST];

		pg_getnameinfo_all(&port->raddr.addr, port->raddr.salen, hostinfo,
				sizeof(hostinfo),
				NULL, 0,
				NI_NUMERICHOST);

#ifdef USE_SSL
		ereport(FATAL,
				(errcode(ERRCODE_INVALID_AUTHORIZATION_SPECIFICATION),
						errmsg("pg_hba.conf rejects connection for host \"%s\", user \"%s\", database \"%s\", %s",
								hostinfo, port->username,
								port->database_name,
								port->ssl ? _("SSL on") : _("SSL off"))));
#else
		ereport(FATAL,
				(errcode(ERRCODE_INVALID_AUTHORIZATION_SPECIFICATION), errmsg("pg_hba.conf rejects connection for host \"%s\", user \"%s\", database \"%s\"", hostinfo, port->user_name, port->database_name)));
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
		char hostinfo[NI_MAXHOST];
		pg_getnameinfo_all(&port->raddr.addr, port->raddr.salen, hostinfo,
				sizeof(hostinfo),
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
								hostinfo, port->username,
								port->database_name,
								port->ssl ? _("SSL on") : _("SSL off")),
						HOSTNAME_LOOKUP_DETAIL(port)));
#else
		ereport(FATAL,
				(errcode(ERRCODE_INVALID_AUTHORIZATION_SPECIFICATION), errmsg("no pg_hba.conf entry for host \"%s\", user \"%s\", database \"%s\"", hostinfo, port->user_name, port->database_name), HOSTNAME_LOOKUP_DETAIL(port)));
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
		logdetail =
				"GSS/SSPI/UNIX domain socket/identd/PAM/LDAP/Cert/RADIUS auth support not available via HTTP (yet).";
		rc = STATUS_ERROR;
		break;

	case uaMD5:
//			if (Db_user_namespace)
//				ereport(FATAL,
//						(errcode(ERRCODE_INVALID_AUTHORIZATION_SPECIFICATION),
//						 errmsg("MD5 authentication is not supported when \"db_user_namespace\" is enabled")));
	case uaPassword:
		if (password == NULL || password[0] == 0)
		{
			rc = STATUS_ERROR;
			logdetail = "User did not provide a password";
		}
		else
		{
			rc = md5_crypt_verify(port, port->user_name, (char *) password,
					&logdetail);
			if (rc != STATUS_OK)
				elog(WARNING, "Password verification failed for user '%s': %s",
						port->user_name,
						logdetail ? logdetail : "no detail available");
		}
		break;

	case uaTrust:
		rc = STATUS_OK;
		break;
	}

	if(rc == STATUS_OK)
		return user_name;
	else
		return NULL;
}

/*
 * Check if the user is logged in; if so, return their username.  If not, return
 * NULL and send an error response.  The username will be deallocated along with the
 * request.
 */
static const char *check_authenticated(struct evhttp_request *req, const char *dbname)
{
	if (is_anonymous(req))
	{
		evhttp_send_error(req, 403,
				"You must log in to view database information");
		return NULL;
	}
	else
	{
		const char *user_name = is_logged_in(req, dbname);
		if (user_name == NULL)
		{
			evhttp_send_error(req, 403, "Bad credentials");
			return NULL;
		}

		return user_name;
	}
}


static void listen_for_http_connections(struct evhttp *http)
{
	char *rawstring;
	List *elemlist = NIL;
	ListCell *l;
	int success = 0;

	/* Need a modifiable copy of ListenAddresses */
	rawstring = pstrdup(restgres_listen_addresses);

	/* Parse string into path components */
	if (!SplitIdentifierString(rawstring, '/', &elemlist))
	{
		/* syntax error in list */
		ereport(FATAL,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("invalid list syntax in parameter \"%s\"", "listen_addresses")));
	}
	else
	{
		foreach(l, elemlist)
		{
			char *curhost = (char *) lfirst(l);
			struct evhttp_bound_socket *handle;

			if (strcmp(curhost, "*") == 0)
				handle = evhttp_bind_socket_with_handle(http, "0.0.0.0",
						restgres_listen_port);

			else
				handle = evhttp_bind_socket_with_handle(http, curhost,
						restgres_listen_port);
			if (handle)
			{
				listen_handles[success] = handle;
				success++;
				ereport(LOG,
						(errmsg("Listening on %s:%d", curhost, restgres_listen_port)));
			}
			else
				ereport(WARNING,
						(errmsg("could not create listen socket for \"%s\"", curhost)));
		}
	}
	if (!success && elemlist != NIL)
		ereport(FATAL, (errmsg("could not create any TCP/IP sockets")));

	list_free(elemlist);
	pfree(rawstring);

}

static void worker_connect_cb(struct evconnlistener *listener, evutil_socket_t fd, struct sockaddr *addr, int socklen, void *cbarg)
{
	pid_t connected_pid=-1;
	uid_t uid;
	gid_t gid;

	if(getpeerpideid(fd, &connected_pid, &uid, &gid) == -1)
	{
		elog(WARNING, "Unable to get connected worker's pid, uid, gid");
	}

	/* Find the corresponding slot to fill */
	/* TODO Should we validate the client is really a restgres worker somehow ? */
	for(int i=0; i < restgres_max_concurrency; i++)
	{
		if(backends[i].state == RestgresBackend_Starting)
		{
			/* Check PID if we can */
			if(connected_pid != -1)
			{
				BgwHandleStatus status = GetBackgroundWorkerPid(backends[i].bgworker_handle, &backends[i].pid);
				if(status != BGWH_STARTED)
					continue;
				if(connected_pid != backends[i].pid)
					continue;
			}
			bufferevent_setfd(backends[i].bev, fd);
			backends[i].state = RestgresBackend_Idle;
			return;
		}
	}

	elog(FATAL, "Background worker connected, but we have no slot waiting for them!");
	closesocket(fd);
}

static void
worker_listener_error_cb(struct evconnlistener *lev, void *arg)
{
	int err = errno;
	elog(FATAL, "Error accepting worker connection fd %d max connections = %d: %s", evconnlistener_get_fd(lev), restgres_max_connections, strerror(err));
	evconnlistener_free(lev);
}

static void listen_for_worker_connections(struct event_base *base)
{
	struct evconnlistener *listener;
	const int flags = LEV_OPT_REUSEABLE|LEV_OPT_CLOSE_ON_EXEC|LEV_OPT_CLOSE_ON_FREE;
	struct addrinfo *addr = get_domain_socket_addr();
	char *path = ((struct sockaddr_un*) addr->ai_addr)->sun_path;

	/* Have to unlink any file already there before creating the socket */
	unlink(path);
	listener = evconnlistener_new_bind(base, worker_connect_cb, NULL,
	    flags,
	    restgres_max_concurrency,
	    addr->ai_addr,
	    addr->ai_addrlen);
	if (!listener)
	{
		elog(ERROR, "Couldn't listen for backend connections: %s", strerror(errno));
		return;
	}
	evconnlistener_set_error_cb(listener, worker_listener_error_cb);
	elog(LOG, "Listening for restgres worker connections at %s with backlog %d", path, restgres_max_concurrency);
}
/*
 * Initialize workspace for a worker process: create the schema if it doesn't
 * already exist.
 */
static void initialize_restgres(struct event_base *base)
{
	struct evhttp *http;

	/* Create a new evhttp object to handle requests. */
	http = evhttp_new(base);
	if (!http)
	{
		elog(ERROR, "Couldn't create evhttp");
		return;
	}

	backends = calloc(sizeof(backends[0]), restgres_max_concurrency);

	/* Set callback for incoming HTTP requests*/
	evhttp_set_gencb(http, restgres_http_cb, (void *) http);

	listen_for_http_connections(http);
	listen_for_worker_connections(base);

	/* Connect to our database */
	BackgroundWorkerInitializeConnection("postgres", NULL);

	request_context = AllocSetContextCreate(CurrentMemoryContext,
		"request temporary context",
		ALLOCSET_DEFAULT_MINSIZE,
		ALLOCSET_DEFAULT_INITSIZE,
		ALLOCSET_DEFAULT_MAXSIZE);
}

static void
terminate_backend(struct restgres_backend* backend)
{
	if (backend->bgworker_handle)
	{
		pid_t worker_pid=0;
		GetBackgroundWorkerPid(backend->bgworker_handle, &worker_pid);
		elog(LOG, "Stopping unneeded backend pid %d, db = %s, user = %s", (int)worker_pid, backend->dbname, backend->username);
		TerminateBackgroundWorker(backend->bgworker_handle);
		pfree(backend->bgworker_handle);
		backend->bgworker_handle = NULL;
	}
	if (backend->bev)
	{
		bufferevent_free(backend->bev);
		backend->bev = NULL;
	}

	if (backend->dbname)
	{
		free(backend->dbname);
		backend->dbname = NULL;
	}

	if (backend->username)
	{
		free(backend->username);
		backend->username = NULL;
	}

}

static struct restgres_backend *
init_backend(struct restgres_backend *backend, struct event_base *base, const char *dbname, const char *user_name)
{
	BackgroundWorker worker = { "" };
	struct evbuffer *output;
	struct evbuffer *meta_temp;
	MemoryContext oldcontext = MemoryContextSwitchTo(TopMemoryContext);

	elog(LOG, "New restgres backend needed, db = %s, user = %s", dbname, user_name);

	/* Recycle the backend if necessary */
	terminate_backend(backend);

	backend->state = RestgresBackend_Starting;
	backend->bev = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS | BEV_OPT_UNLOCK_CALLBACKS);
	backend->dbname = pstrdup(dbname);
	backend->username = pstrdup(user_name);

	/* The first thing the backend will receive is the database and user_name */
	output = bufferevent_get_output(backend->bev);
	meta_temp = evbuffer_new();
	evbuffer_add_netstring_cstring(output, dbname);
	evbuffer_add_netstring_cstring(output, user_name);
	evbuffer_free(meta_temp);

	worker.bgw_main = restgres_backend_main;
	evutil_snprintf(worker.bgw_name, sizeof worker.bgw_name, "restgres %s %s", dbname, user_name);

	worker.bgw_restart_time = BGW_NEVER_RESTART;
	worker.bgw_flags = BGWORKER_SHMEM_ACCESS | BGWORKER_BACKEND_DATABASE_CONNECTION;
	worker.bgw_start_time = BgWorkerStart_RecoveryFinished;
	backend->pid = -1;

	/* Any memory allocation by RegisterDynamicBackgroundWorker, especially the bgworker handler, should survive this call */
	RegisterDynamicBackgroundWorker(&worker, &backend->bgworker_handle);
	MemoryContextSwitchTo(oldcontext);
	return backend;
}

static struct restgres_backend *get_backend(struct event_base *base, const char *dbname, const char *user_name)
{
	int slot_to_reuse = -1;
	int slot_to_reuse_last_used = INT_MAX;
	for(int i=0; i < restgres_max_concurrency; i++)
	{
		switch(backends[i].state)
		{
		case RestgresBackend_Unused:
			/* Found a free one, use it if we don't find a matching idle worker */
			slot_to_reuse = i;
			slot_to_reuse_last_used = 0;
			break;
		case RestgresBackend_Idle:
			if(streql(backends[i].dbname, dbname) && streql(backends[i].username, user_name))
			{
				/* Just what we were looking for! */
				return &backends[i];
			}
			else if(backends[i].last_used < slot_to_reuse_last_used)
			{
				slot_to_reuse = i;
				slot_to_reuse_last_used = backends[i].last_used;
			}
			break;
		case RestgresBackend_Starting:
		case RestgresBackend_Busy:
			/* Don't touch! */
			break;
		}
	}
	if(slot_to_reuse == -1)
	{
		elog(ERROR, "All backends are busy, cannot allocate a new backend!");
		return NULL;
	}
	return init_backend(&backends[slot_to_reuse], base, dbname, user_name);
}

void enqueue_request(const char *dbname, const char *user_name, struct evbuffer *buf, int reply_fd) {
	struct restgres_queued_request *x = malloc(sizeof (struct restgres_queued_request));
	x->dbname = strdup(dbname);
	x->user_name = strdup(user_name);
	x->request = evbuffer_new();
	evbuffer_remove_buffer(buf, x->request, evbuffer_get_length(buf));
	x->reply_fd = reply_fd;
	SIMPLEQ_INSERT_TAIL(&queued_requests, x, next);
}

static void send_to_backend(struct event_base *base, const char *dbname, const char *user_name, struct evbuffer *buf, int reply_fd)
{
	/* Get or launch a backend */
	struct restgres_backend *backend = get_backend(base, dbname, user_name);
	if(backend == NULL)
	{
		enqueue_request(dbname, user_name, buf, reply_fd);
	}
	else
	{
		elog(LOG, "Sending reply fd %d to backend", reply_fd);
		sendfd(bufferevent_getfd(backend->bev), reply_fd);
		elog(LOG, "Sending %d byte request to backend", (int)evbuffer_get_length(buf));
		evbuffer_add_netstring_buffer(bufferevent_get_output(backend->bev), buf, true);
		backend->last_used = message_counter++;
	}
}

/**
 * Convert the request into an SCGI request and send that to a backend for processing.
 */
static void handle_request(struct evhttp_request *req)
{
	struct evhttp_connection* conn = evhttp_request_get_connection(req);
	struct event_base* base = evhttp_connection_get_base(conn);
	const char *path;
	const char *db_start;
	const char *user_name;
	const char *dbname;
	const char *db_end;
	struct evbuffer *input;
	struct evbuffer *header_buf;
	struct evbuffer *buf;
	struct evkeyvalq *headers;
	struct evkeyval *header;
	char lenbuf[16];
	char httpbuf[6];
	int reply_fd;

	path = evhttp_request_get_uri(req);
	if ((db_start = remove_prefix("/db/", path)) != NULL)
	{
		if((db_end = strchr(db_start, '/')) == NULL) // Didn't find any slash after the DB name
		{
			/* /databases/:dbname */
			dbname = db_start;
		}
		else
		{
			/* /databases/:dbname/... */
			dbname = pnstrdup(db_start, db_end - db_start); // Freed as part of the memory context
		}
	}
	else
	{
		/* No database selected, use "postgres" as the database for global operations. */
		dbname = "postgres";
	}

	user_name = check_authenticated(req, dbname);
	if(user_name == NULL)
	{
		// Auth failed, an error was already sent back
		return;
	}

	input = evhttp_request_get_input_buffer(req);
	header_buf = evbuffer_new();
	buf = evbuffer_new();
	headers = evhttp_request_get_input_headers(req);
	reply_fd = bufferevent_getfd(evhttp_connection_get_bufferevent(evhttp_request_get_connection(req)));

	// SCGI formatted request
	sprintf(lenbuf, "%d", (int)evbuffer_get_length(input));
	evbuffer_add_netstring_cstring(header_buf, "CONTENT_LENGTH");
	evbuffer_add_netstring_cstring(header_buf, lenbuf);
	evbuffer_add_netstring_cstring(header_buf, "SCGI");
	evbuffer_add_netstring_cstring(header_buf, "1");
	evbuffer_add_netstring_cstring(header_buf, "HTTP");
	sprintf(httpbuf, "%d.%d", req->major, req->minor);
	evbuffer_add_netstring_cstring(header_buf, httpbuf);
	evbuffer_add_netstring_cstring(header_buf, "REQUEST_METHOD");
	evbuffer_add_netstring_cstring(header_buf, cmd_type_method(evhttp_request_get_command(req)));
	evbuffer_add_netstring_cstring(header_buf, "REQUEST_URI");
	evbuffer_add_netstring_cstring(header_buf, evhttp_request_get_uri(req));

	TAILQ_FOREACH(header, headers, next) {
		evbuffer_add_netstring_cstring(header_buf, header->key);
		evbuffer_add_netstring_cstring(header_buf, header->value);
	}

	evbuffer_add_netstring_buffer(buf, header_buf, true);
	evbuffer_free(header_buf);

	evbuffer_add_buffer(buf, input);
	send_to_backend(base, dbname, user_name, buf, reply_fd);
	evbuffer_free(buf);
}

static void restgres_http_cb(struct evhttp_request *req, void *arg)
{
	struct evkeyvalq *headers;
	struct evkeyval *header;
	struct evbuffer *buf;
	MemoryContext oldcontext;
	AssertArg(MemoryContextIsValid(request_context));
	oldcontext = MemoryContextSwitchTo(request_context);

	SetCurrentStatementStartTimestamp();
	StartTransactionCommand();
	SPI_connect();
	PushActiveSnapshot(GetTransactionSnapshot());
	pgstat_report_activity(STATE_RUNNING, "Handling request");
	elog(LOG, "%s %s", cmd_type_method(evhttp_request_get_command(req)), evhttp_request_get_uri(req));

	headers = evhttp_request_get_input_headers(req);
	for (header = headers->tqh_first; header; header = header->next.tqe_next)
	{
		elog(LOG, "  %s: %s", header->key, header->value);
	}

	buf = evhttp_request_get_input_buffer(req);
	elog(LOG, "Input data:");
	while (evbuffer_get_length(buf))
	{
		int n;
		char cbuf[128];
		n = evbuffer_remove(buf, cbuf, sizeof(cbuf));
		if (n > 0)
			(void) fwrite(cbuf, 1, n, stdout);
	}

	handle_request(req);

	SPI_finish();
	PopActiveSnapshot();
	CommitTransactionCommand();
	pgstat_report_activity(STATE_IDLE, NULL);
	MemoryContextSwitchTo(oldcontext);
	MemoryContextReset(request_context);
}

void restgres_main(Datum main_arg)
{
	struct event_base *base;

	base = event_base_new();
	if (!base)
	{
		elog(ERROR, "Couldn't create event_base");
		proc_exit(1);
		return;
	}

	watch_for_signals_and_postmaster_death(base);

	/* We're now ready to receive signals */
	BackgroundWorkerUnblockSignals();

	initialize_restgres(base);

	/* Start up at least one backend, for testing */
	get_backend(base, "postgres", "postgres");

	elog(LOG, "RESTgres initialized, pid %d port %d listen_addresses \"%s\"",
			getpid(), restgres_listen_port, restgres_listen_addresses);

	event_base_dispatch(base);

	proc_exit(0);
}

