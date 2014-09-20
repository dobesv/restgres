#include "unistd.h"

#include "postgres.h"

/* These are always necessary for a bgworker */
#include "miscadmin.h"

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
#include "catalog/pg_database.h"
#include "catalog/indexing.h"
#include "utils/fmgroids.h"
#include "access/htup_details.h"
#include "storage/lmgr.h"

#include <event2/http.h>
#include <event2/util.h>
#include <event2/keyvalq_struct.h>

#include "routes.h"
#include "jsonbuf.h"
#include "util.h"
#include "content_types.h"

/* When we get here, the database we are asking about is the one we are connected to ... */
void
db_route_GET(struct restgres_request *req)
{
	struct jsonbuf *jp = req->jsonbuf;
	add_json_content_type_header(req->reply_headers);
	jsonbuf_start_document(jp);
	jsonbuf_member_start_object(jp, "database");

	jsonbuf_end_object(jp);
	jsonbuf_end_document(jp);
}
