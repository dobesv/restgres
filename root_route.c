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
#include "routes.h"


void
root_route_GET(struct restgres_request *req)
{
	add_json_content_type_header(req->reply_headers);
	evbuffer_add_cstring(req->reply_buffer, "{\r\n");
	evbuffer_add_json_cstring_pair(req->reply_buffer, "version", PG_VERSION_STR);
	evbuffer_add_crlf(req->reply_buffer);
	evbuffer_add_cstring(req->reply_buffer, "}\r\n");
}
