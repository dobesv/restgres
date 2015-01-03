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
#include "catalog/pg_authid.h"
#include "catalog/pg_class.h"
#include "catalog/indexing.h"
#include "utils/fmgroids.h"
#include "access/htup_details.h"
#include "storage/lmgr.h"
#include "mb/pg_wchar.h"
#include "utils/syscache.h"

#include <event2/http.h>
#include <event2/util.h>
#include <event2/keyvalq_struct.h>

#include "routes.h"
#include "jsonbuf.h"
#include "util.h"
#include "content_types.h"

void
jsonbuf_add_table_row_data(struct jsonbuf *jp, Oid oid, const char *uri, Form_pg_class form);


void
jsonbuf_add_table_row_data(struct jsonbuf *jp, Oid oid, const char *uri, Form_pg_class form)
{
}

void
table_row_route_GET(struct restgres_request *req)
{
	struct jsonbuf *jp = req->jsonbuf;
	const char     *tablename = evhttp_find_header(req->matchdict, "tablename");
	const char     *schemaname = evhttp_find_header(req->matchdict, "schemaname");
	Oid             schemaOid = GetSysCacheOid1(NAMESPACENAME, PointerGetDatum(schemaname));
	Oid             tableOid;

	if (!OidIsValid(schemaOid))
	{
		elog(ERROR, "lookup failed for schema '%s' in database '%s'", schemaname, evhttp_find_header(req->matchdict, "dbname"));
		req->status_code = 404;
		return;
	}

	tableOid = GetSysCacheOid2(RELNAMENSP, PointerGetDatum(tablename), schemaOid);
	if (!OidIsValid(tableOid))
	{
		elog(ERROR, "lookup failed for table '%s' in schema '%s' in database '%s'", tablename, schemaname, evhttp_find_header(req->matchdict, "dbname"));
		req->status_code = 404;
		return;
	}

	jsonbuf_start_document(jp);

	jsonbuf_end_document(jp);
}
