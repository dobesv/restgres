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
#include "sendrecvfd.h"
#include "response_phrase.h"

/* flags set by signal handlers */
static volatile sig_atomic_t got_sighup = false;
static volatile sig_atomic_t got_sigterm = false;
static volatile sig_atomic_t lost_connection_to_master = false;

static pgsocket
connect_to_master();

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

/* Add a correct "Date" header to headers, unless it already has one. */
static void
add_date_header(struct evkeyvalq *headers)
{
	char date[50];
#ifndef _WIN32
	struct tm cur;
#endif
	struct tm *cur_p;
	time_t t = time(NULL);
#ifdef _WIN32
	cur_p = gmtime(&t);
#else
	gmtime_r(&t, &cur);
	cur_p = &cur;
#endif
	if (strftime(date, sizeof(date),
		"%a, %d %b %Y %H:%M:%S GMT", cur_p) != 0) {
		evhttp_add_header(headers, "Date", date);
	}
}

#if defined(__STDC__) && defined(__STDC_VERSION__)
#if (__STDC_VERSION__ >= 199901L)
#define EV_SIZE_FMT "%zu"
#define EV_SSIZE_FMT "%zd"
#define EV_SIZE_ARG(x) (x)
#define EV_SSIZE_ARG(x) (x)
#endif
#endif

#ifndef EV_SIZE_FMT
#if (EVENT__SIZEOF_SIZE_T <= EVENT__SIZEOF_LONG)
#define EV_SIZE_FMT "%lu"
#define EV_SSIZE_FMT "%ld"
#define EV_SIZE_ARG(x) ((unsigned long)(x))
#define EV_SSIZE_ARG(x) ((long)(x))
#else
#define EV_SIZE_FMT EV_U64_FMT
#define EV_SSIZE_FMT EV_I64_FMT
#define EV_SIZE_ARG(x) EV_U64_ARG(x)
#define EV_SSIZE_ARG(x) EV_I64_ARG(x)
#endif
#endif

static void
evhttp_maybe_add_content_length_header(struct evkeyvalq *headers, size_t content_length);
static void
evbuffer_add_http_response(int status_code, const char *http_ver, struct evkeyvalq *headers, struct evbuffer *reply_body, struct evbuffer *reply_buffer);
static void
evbuffer_parse_scgi_headers(struct evbuffer *input, struct evkeyvalq *headers);
static int
backend_handle_request(struct evkeyvalq *headers, struct evbuffer *body_buffer, struct evkeyvalq *reply_headers, struct evbuffer *reply_buffer);



/* Add a "Content-Length" header with value 'content_length' to headers,
 * unless it already has a content-length or transfer-encoding header. */
static void
evhttp_maybe_add_content_length_header(struct evkeyvalq *headers, size_t content_length)
{
	if (evhttp_find_header(headers, "Transfer-Encoding") == NULL &&
	    evhttp_find_header(headers,	"Content-Length") == NULL) {
		char len[22];
		evutil_snprintf(len, sizeof(len), EV_SIZE_FMT,
		    EV_SIZE_ARG(content_length));
		evhttp_add_header(headers, "Content-Length", len);
	}
}

static void
evbuffer_add_http_response(int status_code, const char *http_ver, struct evkeyvalq *reply_headers, struct evbuffer *reply_body, struct evbuffer *reply_buffer)
{
	/* Make sure we have Date and Content-Length */
	evhttp_maybe_add_content_length_header(reply_headers, evbuffer_get_length(reply_body));

	/* TODO figure out the right HTTP version to return */
	evbuffer_add_printf(reply_buffer, "HTTP/%s %d %s\r\n", http_ver, status_code, http_response_phrase(status_code));
	evbuffer_add_headers(reply_buffer, reply_headers);
	evbuffer_add_crlf(reply_buffer);
	evbuffer_remove_buffer(reply_body, reply_buffer, evbuffer_get_length(reply_body));
	/* elog(LOG, "Reply: %.*s", (int)evbuffer_get_length(reply_buffer), evbuffer_pullup(reply_buffer, -1)); */
}

static int
backend_handle_request(struct evkeyvalq *headers, struct evbuffer *body_buffer, struct evkeyvalq *reply_headers, struct evbuffer *reply_buffer)
{
	evhttp_add_header(reply_headers, "Content-Type", "application/json; charset=utf8");
	evbuffer_add_cstring(reply_buffer, "{\"what\":\"TODO\"}\r\n");
	return 200;
}

static void
evbuffer_parse_scgi_headers(struct evbuffer *input, struct evkeyvalq *headers)
{
	char *key;
	/* elog(LOG, "Headers: %.*s", (int)evbuffer_get_length(input), (char *)evbuffer_pullup(input, -1)); */
	while((key = evbuffer_remove_netstring_cstring(input)) != NULL)
	{
		char *value = evbuffer_remove_netstring_cstring(input);
		if(value == NULL)
			break;
		evhttp_add_header(headers, key, value);
		/* elog(LOG, "Got header; %s: %s", key, value); */
	}
	if(evbuffer_get_length(input) != 0)
	{
		elog(FATAL, "Invalid headers block; should be an even number of properly formatted netstrings");
		proc_exit(1);
	}
}

void restgres_backend_main(Datum main_arg)
{
	pgsocket fd;
	char *dbname = NULL;
	char *username = NULL;
	struct evbuffer *input = evbuffer_new();
	struct evbuffer *request_buffer = evbuffer_new();
	struct evbuffer *headers_buffer = evbuffer_new();
	struct evbuffer *body_buffer = evbuffer_new();
	struct evbuffer *reply_buffer = evbuffer_new();
	struct evbuffer *reply_body_buffer = evbuffer_new();
	const char *http_ver;

	pgsocket reply_fd = PGINVALID_SOCKET;

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
	dbname = read_netstring_cstring(fd, input, 1000);
	username = read_netstring_cstring(fd, input, 1000);
	if(dbname == NULL || username == NULL)
	{
		elog(FATAL, "Failed to read database and username from master");
		proc_exit(1);
	}

	BackgroundWorkerInitializeConnection(dbname, username);
	elog(LOG, "restgres backend worker initialized, pid = %d, user = %s, dbname = %s", getpid(), dbname, username);

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
			if(reply_fd == PGINVALID_SOCKET)
			{
				reply_fd = recvfd(fd);
			}

			if(read_netstring_buffer(fd, input, request_buffer, 65536) == 0)
			{
				MemoryContext oldcontext = MemoryContextSwitchTo(request_context);
				struct evkeyvalq request_headers = TAILQ_HEAD_INITIALIZER(request_headers);
				struct evkeyvalq reply_headers = TAILQ_HEAD_INITIALIZER(reply_headers);
				int status_code;

				/* Notify master we are busy with that request */
				if(write(fd, "B", 1) < 0)
				{
					elog(FATAL, "Error sending status 'B' to master.");
					proc_exit(1);
				}

				if(reply_fd == PGINVALID_SOCKET)
				{
					/* Internal error */
					elog(FATAL, "Must receive reply fd before request");
					proc_exit(1);
				}

				/* Pull out the headers, they are in their own little blob */
				if(evbuffer_remove_netstring_buffer(request_buffer, headers_buffer) != 0)
				{
					elog(FATAL, "Invalid request payload from master: doesn't start with a netstring with all the headers");
					proc_exit(1);
				}

				/* Remaining bytes after the header go into the body */
				evbuffer_remove_buffer(request_buffer, body_buffer, evbuffer_get_length(request_buffer));

				/* Parse headers */
				evbuffer_parse_scgi_headers(headers_buffer, &request_headers);

				http_ver = evhttp_find_header(&request_headers, "http");

				/* Always return a Date header */
				add_date_header(&reply_headers);

				/* Now pass those pieces off to the handler */
				status_code = backend_handle_request(&request_headers, body_buffer, &reply_headers, reply_body_buffer);

				/* Collect the response line, headers, and body into a buffer to send */
				evbuffer_add_http_response(status_code, http_ver, &reply_headers, reply_body_buffer, reply_buffer);

				/* Drain the body buffer if the handler didn't already do that */
				evbuffer_drain(body_buffer, evbuffer_get_length(body_buffer));

				/* Free headers */
				evhttp_clear_headers(&reply_headers);
				evhttp_clear_headers(&request_headers);

				/* Write out the reply */
				while(evbuffer_get_length(reply_buffer) > 0)
				{
					if(evbuffer_write(reply_buffer, reply_fd) < 0)
					{
						elog(WARNING, "Error writing reply to client: %s", strerror(errno));
						evbuffer_drain(reply_buffer, evbuffer_get_length(reply_buffer));
						break;
					}
				}

				/* Close reply_fd - no keep-alive support for now */
				close(reply_fd);

				/* Reset reply_fd so we get a new one */
				reply_fd = PGINVALID_SOCKET;

				MemoryContextSwitchTo(oldcontext);
				MemoryContextReset(request_context);

				/* Notify master we are done with that request */
				if(write(fd, "I", 1) < 0)
				{
					elog(FATAL, "Error sending status 'I' to master.");
					proc_exit(1);
				}

			}
		}
	}

	proc_exit(1);
}
