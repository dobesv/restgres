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

#include "util.h"
#include "backend.h"
#include "master.h"
#include "bgwutil.h"

struct evutil_addrinfo *
get_domain_socket_addr();

/*
 * Signal handler for SIGTERM
 *		Set a flag to let the main loop to terminate, and set our latch to wake
 *		it up.
 */
static void
restgres_sigterm(evutil_socket_t s, short what, void *arg)
{
	event_base_loopbreak((struct event_base *) arg);
}

/*
 * Signal handler for SIGHUP
 *		Set a flag to tell the main loop to reread the config file, and set
 *		our latch to wake it up.
 */
static void
restgres_sighup(evutil_socket_t s, short what, void *arg)
{
	ProcessConfigFile(PGC_SIGHUP);
}

/*
 * Handler for a death notification from the postmaster
 */
static void
postmaster_death_cb(evutil_socket_t s, short what, void *arg)
{
	event_base_loopbreak((struct event_base *) arg);
}

void
watch_for_signals_and_postmaster_death(struct event_base *base)
{
	/* Watch for SIGHUP and SIGTERM */
	evsignal_new(base, SIGHUP, (event_callback_fn )restgres_sighup, base);
	evsignal_new(base, SIGTERM, (event_callback_fn )restgres_sigterm, base);

	/* Watch for postmaster death; if the postmaster goes, we'll exit too */
	event_new(base, postmaster_alive_fds[POSTMASTER_FD_WATCH], EV_READ,
			postmaster_death_cb, (void *) base);

}

struct evutil_addrinfo *
get_domain_socket_addr()
{
	static struct sockaddr_un address = {0};
	static struct evutil_addrinfo addrinfo = {0};
	address.sun_family = AF_LOCAL;
	strcpy(address.sun_path, "/tmp/restgres.sock");
	addrinfo.ai_addr = (struct sockaddr *)&address;
	addrinfo.ai_addrlen = sizeof(address);
	addrinfo.ai_family = AF_LOCAL;
	addrinfo.ai_socktype = SOCK_STREAM;
	return &addrinfo;
}
