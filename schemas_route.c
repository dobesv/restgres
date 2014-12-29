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
#include "catalog/pg_namespace.h"
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
jsonbuf_add_schema_info(struct jsonbuf *jp, Oid oid, const char *uri, Form_pg_namespace dbform);

void
jsonbuf_add_schemas(struct jsonbuf *jp, const char *uri);


void
jsonbuf_add_schemas(struct jsonbuf *jp, const char *uri)
{
	Relation	relation;
	SysScanDesc scan;
	HeapTuple	tuple;
	Oid			oid;

	jsonbuf_member_start_array(jp, "schemas");

	relation = heap_open(NamespaceRelationId, AccessShareLock);

	scan = systable_beginscan(relation, InvalidOid, false,
							  NULL, 0, NULL);
	while (HeapTupleIsValid(tuple = systable_getnext(scan)))
	{
		Form_pg_namespace  form = (Form_pg_namespace) GETSTRUCT(tuple);
		const char        *schema_uri = pstr_uri_append_path_component(uri, NameStr(form->nspname));

		oid = HeapTupleGetOid(tuple);

		jsonbuf_element_start_object(jp);

		jsonbuf_add_schema_info(jp, oid, schema_uri, form);

		jsonbuf_end_object(jp);
	}

	systable_endscan(scan);

	heap_close(relation, AccessShareLock);

	jsonbuf_end_array(jp);

}

void
schemas_route_GET(struct restgres_request *req)
{
	struct jsonbuf *jp = req->jsonbuf;
	add_json_content_type_header(req->reply_headers);
	jsonbuf_start_document(jp);
	jsonbuf_add_schemas(jp, evhttp_uri_get_path(req->uri));
	jsonbuf_end_document(jp);
}
