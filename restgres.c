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

/*
 * Entrypoint of this module.
 *
 * We register more than one worker process here, to demonstrate how that can
 * be done.
 */
void _PG_init(void)
{
	struct BackgroundWorker worker = { "restgres master" };

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
