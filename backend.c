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
#include <event2/listener.h>
#include <event2/util.h>
#include <event2/keyvalq_struct.h>
#include <event2/bufferevent.h>

#include <sys/queue.h>
#include <time.h>

#include "util.h"
#include "backend.h"
#include "master.h"
#include "bgwutil.h"
#include "response_phrase.h"
#include "routes.h"
#include "jsonbuf.h"

/* flags set by signal handlers */
static volatile sig_atomic_t got_sighup = false;
static volatile sig_atomic_t got_sigterm = false;

static pgsocket
connect_to_master();

static void
evbuffer_add_response(int status_code, struct evkeyvalq *headers, struct evbuffer *reply_body, struct evbuffer *reply_buffer);

/*
 * Signal handler for SIGTERM
 *		Set a flag to let the main loop to terminate, and set our latch to wake
 *		it up.
 */
static void
worker_spi_sigterm(SIGNAL_ARGS)
{
	int			save_errno = errno;

	got_sigterm = true;
	if (MyProc)
		SetLatch(&MyProc->procLatch);

	errno = save_errno;
}

/*
 * Signal handler for SIGHUP
 *		Set a flag to tell the main loop to reread the config file, and set
 *		our latch to wake it up.
 */
static void
worker_spi_sighup(SIGNAL_ARGS)
{
	int			save_errno = errno;

	got_sighup = true;
	if (MyProc)
		SetLatch(&MyProc->procLatch);

	errno = save_errno;
}

static pgsocket
connect_to_master()
{
	struct evutil_addrinfo *addrinfo = get_domain_socket_addr();
	pgsocket fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if(fd == -1)
	{
		elog(FATAL, "Unable to create a socket: %s", strerror(errno));
		return -1;
	}
	if(connect(fd, addrinfo->ai_addr, addrinfo->ai_addrlen) == -1)
	{
		elog(FATAL, "Unable to connect to restgres master at %s: %s", ((struct sockaddr_un *)addrinfo->ai_addr)->sun_path, strerror(errno));
		return -1;
	}
	return fd;
}

static void
evbuffer_add_response(int status_code, struct evkeyvalq *reply_headers, struct evbuffer *reply_body, struct evbuffer *reply_buffer)
{
	struct evkeyval *header;
	struct evbuffer *header_buf = evbuffer_new();

	evbuffer_add_netstring_cstring(header_buf, "Content-Length");
	evbuffer_add_netstring_printf(header_buf, "%d", evbuffer_get_length(reply_body));
	if(status_code != 200)
	{
		evbuffer_add_netstring_cstring(header_buf, "STATUS");
		evbuffer_add_netstring_printf(header_buf, "%d", status_code);
	}

	TAILQ_FOREACH(header, reply_headers, next) {
		evbuffer_add_netstring_cstring(header_buf, header->key);
		evbuffer_add_netstring_cstring(header_buf, header->value);
	}

	evbuffer_add_netstring_buffer(reply_buffer, header_buf, true);
	evbuffer_remove_buffer(reply_body, reply_buffer, evbuffer_get_length(reply_body));
}


void restgres_backend_main(Datum main_arg)
{
	pgsocket fd;
	char *dbname = NULL;
	char *username = NULL;
	const char *http_ver = NULL;
	struct evbuffer *input = evbuffer_new();
	struct evbuffer *request_buffer = evbuffer_new();
	struct evbuffer *headers_buffer = evbuffer_new();
	struct evbuffer *body_buffer = evbuffer_new();
	struct evbuffer *reply_buffer = evbuffer_new();
	struct evbuffer *reply_body_buffer = evbuffer_new();
	struct evkeyvalq request_headers = TAILQ_HEAD_INITIALIZER(request_headers);
	struct evkeyvalq reply_headers = TAILQ_HEAD_INITIALIZER(reply_headers);
	struct evkeyvalq query_params = TAILQ_HEAD_INITIALIZER(query_params);
	struct evkeyvalq matchdict = TAILQ_HEAD_INITIALIZER(matchdict);
	struct jsonbuf jsonbuf = {0, reply_body_buffer};
	struct restgres_request req = {
			0,
			-1,
			NULL,
			0,
			NULL,
			&request_headers,
			&query_params,
			body_buffer,
			&reply_headers,
			reply_body_buffer,
			&matchdict,
			&jsonbuf
	};
	MemoryContext request_context = AllocSetContextCreate(CurrentMemoryContext,
			"request temporary context",
			ALLOCSET_DEFAULT_MINSIZE,
			ALLOCSET_DEFAULT_INITSIZE,
			ALLOCSET_DEFAULT_MAXSIZE);

	/* Establish signal handlers before unblocking signals. */
	pqsignal(SIGHUP, worker_spi_sighup);
	pqsignal(SIGTERM, worker_spi_sigterm);

	/* We're now ready to receive signals */
	BackgroundWorkerUnblockSignals();

	fd = connect_to_master();
	if(fd == -1)
	{
		proc_exit(1);
		return;
	}

	/* This must be the initial packet telling us what database to connect to */
	dbname = read_netstring_cstring(fd, input, 32);
	username = read_netstring_cstring(fd, input, 32);
	if(dbname == NULL || username == NULL)
	{
		elog(FATAL, "Failed to read database and username from master");
		proc_exit(1);
	}

	BackgroundWorkerInitializeConnection(dbname, username);
	elog(LOG, "restgres backend worker initialized, pid = %d, username = %s, dbname = %s", getpid(), username, dbname);

	/*
	 * Main loop: do this until the SIGTERM handler tells us to terminate
	 */
	while (!got_sigterm)
	{
		int			rc;

		/*
		 * Background workers mustn't call usleep() or any direct equivalent:
		 * instead, they may wait on their process latch, which sleeps as
		 * necessary, but is awakened if postmaster dies.  That way the
		 * background process goes away immediately in an emergency.
		 */
		rc = WaitLatchOrSocket(&MyProc->procLatch,
					   WL_LATCH_SET | WL_POSTMASTER_DEATH | WL_SOCKET_READABLE,
					   fd,
					   0);
		ResetLatch(&MyProc->procLatch);

		/* emergency bailout if postmaster has died */
		if (rc & WL_POSTMASTER_DEATH)
			proc_exit(1);

		/* In case of timeout, we're just idling so exit */
		if (rc & WL_TIMEOUT)
			proc_exit(0);

		/* In case of a SIGHUP, exit and get restarted */
		if (got_sighup)
			proc_exit(0);

		if (rc & WL_SOCKET_READABLE)
		{
			if(read_netstring_buffer(fd, input, request_buffer, 65536) == -1)
			{
				elog(FATAL, "Error reading request from master");
				proc_exit(1);
			}
			else
			{
				MemoryContext oldcontext = MemoryContextSwitchTo(request_context);
				struct restgres_route *best_route;

				/* Pull out the headers, they are in their own little blob */
				if(evbuffer_remove_netstring_buffer(request_buffer, headers_buffer) != 0)
				{
					elog(FATAL, "Invalid request payload from master: doesn't start with a netstring with all the headers");
					proc_exit(1);
				}

				/* Remaining bytes after the header go into the body */
				evbuffer_remove_buffer(request_buffer, body_buffer, evbuffer_get_length(request_buffer));

				/* Parse headers */
				if(evbuffer_parse_scgi_headers(headers_buffer, &request_headers) == -1)
				{
					elog(ERROR, "Bad headers blob from master!");
					proc_exit(1);
				}

				req.http_ver = http_ver = evhttp_find_header(&request_headers, "http");
				req.cmd_type = method_cmd_type(evhttp_find_header(&request_headers, "request_method"));

				/* Pre-parse the URI and query parameters, for convenience */
				req.uri = evhttp_uri_parse(evhttp_find_header(req.headers, "request_uri"));
				evhttp_parse_query_str(evhttp_uri_get_query(req.uri), &query_params);

				/* Default status is 404, meaning we never matched any route */
				req.status_code = 404;

				/* Now pass those pieces off to the handler */
				best_route = find_best_route(&req);
				if(best_route != NULL)
				{
					elog(LOG, "Request matches route %s", best_route->name);

					/* Default to status 200 if they don't set an error */
					req.status_code = 200;

					/* Fill in the matchdict */
					parse_route_uri_pattern(evhttp_uri_get_path(req.uri), best_route->pattern, &matchdict);

					/* Start a transaction */
					SetCurrentStatementStartTimestamp();
					StartTransactionCommand();
					SPI_connect();
					PushActiveSnapshot(GetTransactionSnapshot());
					pgstat_report_activity(STATE_RUNNING, "Handling request");

					/* Invoke the handler */
					best_route->handler(&req);

					/* Transaction done */
					SPI_finish();
					PopActiveSnapshot();
					CommitTransactionCommand();
					pgstat_report_activity(STATE_IDLE, NULL);

					if(best_route->response_content_type != NULL && evhttp_find_header(&reply_headers, "Content-Type") == NULL)
					{
						evhttp_add_header(&reply_headers, "Content-Type", best_route->response_content_type);
					}
				}
				else
				{
					/* Not found */
					req.status_code = 404;
				}

				/* Don't send any body if the request is a HEAD request */
				if(req.cmd_type == EVHTTP_REQ_HEAD)
				{
					evbuffer_drain(reply_body_buffer, evbuffer_get_length(reply_body_buffer));
				}

				/* Collect the response line, headers, and body into a buffer to send */
				evbuffer_add_response(req.status_code, &reply_headers, reply_body_buffer, reply_buffer);

				/* Drain the body buffer if the handler didn't already do that */
				evbuffer_drain(body_buffer, evbuffer_get_length(body_buffer));

				/* Free headers */
				evhttp_clear_headers(&reply_headers);
				evhttp_clear_headers(&request_headers);
				evhttp_clear_headers(&query_params);
				evhttp_clear_headers(&matchdict);
				if(req.uri)
				{
					evhttp_uri_free(req.uri);
					req.uri = NULL;
				}

				/* Write out the reply */
				while(evbuffer_get_length(reply_buffer) > 0)
				{
					if(evbuffer_write(reply_buffer, fd) < 0)
					{
						elog(WARNING, "Error writing reply to master: %s", strerror(errno));
						proc_exit(1);
						break;
					}
				}

				MemoryContextSwitchTo(oldcontext);
				MemoryContextReset(request_context);
			}
		}
	}

	proc_exit(1);
}
