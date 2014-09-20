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
#include "libpq/libpq.h"
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

void
root_route_GET(struct restgres_request *req)
{
	struct jsonbuf *jp = req->jsonbuf;
	jsonbuf_start_document(jp);
	jsonbuf_member_cstring(jp, "version", PG_VERSION_STR);

	jsonbuf_member_start_array(jp, "links");
	jsonbuf_element_link(jp, "self", SERVER_METADATA_TYPE_V1, "/");
	jsonbuf_element_link(jp, "tablespaces", TABLESPACE_LIST_TYPE_V1, "/tablespaces");
	jsonbuf_element_link(jp, "databases", DATABASE_LIST_TYPE_V1, "/databases");
	jsonbuf_element_link(jp, "roles", ROLE_LIST_TYPE_V1, "/roles");
	jsonbuf_end_array(jp);

	jsonbuf_end_document(jp);


}
