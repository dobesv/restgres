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

#include <sys/queue.h>

#include "bgwutil.h"
#include "util.h"
#include "backend.h"
#include "master.h"

PG_MODULE_MAGIC
;

void
_PG_init(void);

static void resource_root_GET(struct evhttp_request *req)
{
	struct evbuffer *databuf;
	databuf = evbuffer_new();
	evbuffer_add_printf(databuf, "{\n"
			"    \"version\":\"" PG_VERSION "\"\n"
	"    \"version_num\":%d\n"
	"}\n", PG_VERSION_NUM);
	evhttp_add_header(evhttp_request_get_output_headers(req), "Server",
			"RESTgres");
	evhttp_add_header(evhttp_request_get_output_headers(req), "Content-Type",
			"text/plain");
	evhttp_send_reply(req, 200, "OK", databuf);
	evbuffer_free(databuf);
}

static void resource_root(struct evhttp_request *req)
{
	switch (evhttp_request_get_command(req))
	{
	case EVHTTP_REQ_GET:
		resource_root_GET(req);
		return;
	default:
		evhttp_send_error(req, 405, "Method not supported");
		return;
	}
}

static void resource_databases_GET_json(struct evhttp_request *req)
{
	int ret;
	HeapTuple spi_tuple;
	SPITupleTable *spi_tuptable = SPI_tuptable;
	TupleDesc spi_tupdesc = spi_tuptable->tupdesc;
	const char *datname;
	struct evbuffer *buf;

	buf = evbuffer_new();
	evbuffer_add_printf(buf, "{\n  \"databases\": ");

	ret = SPI_execute(
			"SELECT datname FROM pg_database WHERE datistemplate = false;",
			true, 0);
	if (ret != SPI_OK_SELECT)
		elog(FATAL, "SPI_execute failed: error code %d", ret);
	if (SPI_processed == 0)
		evbuffer_add_cstring(buf, "[]\n");
	else
	{
		evbuffer_add_cstring(buf, "[");
		for (int i = 0; i < SPI_processed; i++)
		{
			StringInfo name_buf = makeStringInfo();
			spi_tuptable = SPI_tuptable;
			spi_tupdesc = spi_tuptable->tupdesc;
			spi_tuple = SPI_tuptable->vals[i];
			datname = SPI_getvalue(spi_tuple, spi_tupdesc, 1);
			escape_json(name_buf, datname);
			evbuffer_add_cstring(buf, i == 0 ? "\n    " : ",\n    ");
			evbuffer_add_cstring(buf, "{ \"name\":");
			evbuffer_add_cstring(buf, name_buf->data);
			evbuffer_add_cstring(buf, " }");
		}

		evbuffer_add_cstring(buf, "\n  ]\n");
	}
	evbuffer_add_cstring(buf, "}\n");
	evhttp_add_header(evhttp_request_get_output_headers(req), "Server",
			"RESTgres");
	evhttp_add_header(evhttp_request_get_output_headers(req), "Content-Type",
			"application/json; charset=utf8");
	evhttp_send_reply(req, 200, "OK", buf);
	evbuffer_free(buf);

}

static void resource_databases_GET(struct evhttp_request *req)
{
	// TODO Content-type negotiation
	resource_databases_GET_json(req);
}

static void resource_databases(struct evhttp_request *req)
{
	const char *user_name;
	if ((user_name = check_authenticated(req, "postgres")) != NULL)
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

static void resource_database_GET(struct evhttp_request *req, const char *database)
{
	/*
	 * Desired fields:
	 *
	 * name
	 * oid
	 * owner
	 * acl
	 * tablespace
	 * default tablespace
	 * encoding
	 * collation
	 * character type
	 * default schema
	 * default table acl
	 * default sequence acl
	 * default function acl
	 * default type acl
	 * system database?
	 * comment
	 */
	evhttp_send_error(req, 405, "Database metadata not implemented yet.");
}

static void resource_database(struct evhttp_request *req, const char *database)
{
	const char *user_name;
	if ((user_name = check_authenticated(req, database)) != NULL)
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

/*
 * Entrypoint of this module.
 *
 * We register more than one worker process here, to demonstrate how that can
 * be done.
 */
void _PG_init(void)
{
	struct BackgroundWorker worker = { "RESTgres worker" };

	/* get the configuration */
	DefineCustomStringVariable("http.listen_addresses",
			"Addresses to listen on; see PostgreSQL listen_addresses",
			NULL, &restgres_listen_addresses, "*", PGC_SIGHUP, 0,
			NULL,
			NULL,
			NULL);
	DefineCustomIntVariable("http.port",
			"Port to listen on (default: any available port)",
			NULL, &restgres_listen_port, restgres_listen_port, 0, 32768,
			PGC_SIGHUP, 0,
			NULL,
			NULL,
			NULL);
	DefineCustomIntVariable("http.max_connections",
			"Maximum number of connections to serve at once (additional connections will have to wait or be rejected)",
			NULL, &restgres_max_connections, 100, 0,
			INT_MAX, PGC_SIGHUP, 0,
			NULL,
			NULL,
			NULL);
	DefineCustomIntVariable("http.max_concurrency",
			"Maximum number of connections to serve at once (additional connections will have to wait or be rejected)",
			NULL, &restgres_max_concurrency, 100, 0,
			INT_MAX, PGC_SIGHUP, 0,
			NULL,
			NULL,
			NULL);

	/* set up common data for all our workers */
	worker.bgw_flags = BGWORKER_SHMEM_ACCESS
			| BGWORKER_BACKEND_DATABASE_CONNECTION;
	worker.bgw_restart_time = BGW_DEFAULT_RESTART_INTERVAL;
	worker.bgw_start_time = BgWorkerStart_RecoveryFinished;
	worker.bgw_main = restgres_main;
	worker.bgw_notify_pid = 0;

	RegisterBackgroundWorker(&worker);
}
