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
#include "catalog/pg_authid.h"
#include "catalog/pg_tablespace.h"
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
jsonbuf_add_database_info(struct jsonbuf *jp, Oid oid, Form_pg_database dbform);

void
jsonbuf_add_databases(struct jsonbuf *jp);

void
jsonbuf_add_databases(struct jsonbuf *jp)
{
	Relation	relation;
	SysScanDesc scan;
	HeapTuple	tuple;
	Oid			dbOid;


	jsonbuf_member_start_array(jp, "databases");

	relation = heap_open(DatabaseRelationId, AccessShareLock);

	scan = systable_beginscan(relation, InvalidOid, false,
							  NULL, 0, NULL);
	while (HeapTupleIsValid(tuple = systable_getnext(scan)))
	{
		Form_pg_database dbform = (Form_pg_database) GETSTRUCT(tuple);
		dbOid = HeapTupleGetOid(tuple);

		jsonbuf_element_start_object(jp);

		jsonbuf_add_database_info(jp, dbOid, dbform);

		jsonbuf_end_object(jp);
	}

	systable_endscan(scan);

	heap_close(relation, AccessShareLock);

	jsonbuf_end_array(jp);

}

void
databases_route_GET(struct restgres_request *req)
{
	struct jsonbuf *jp = req->jsonbuf;
	add_json_content_type_header(req->reply_headers);
	jsonbuf_start_document(jp);
	jsonbuf_add_databases(jp);
	jsonbuf_end_document(jp);
}
