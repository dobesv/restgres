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
jsonbuf_add_table_info(struct jsonbuf *jp, Oid oid, const char *uri, Form_pg_class dbform);

void
jsonbuf_add_tables(struct jsonbuf *jp, const char *uri, Oid schemaOid, char kind);


void
jsonbuf_add_tables(struct jsonbuf *jp, const char *uri, Oid schemaOid, char kind)
{
	Relation	relation;
	SysScanDesc scan;
	HeapTuple	tuple;
	Oid			oid;
	ScanKeyData key[2];

	jsonbuf_member_start_array(jp, "tables");

	relation = heap_open(RelationRelationId, AccessShareLock);

	// Filter on OID, to match the schema we're scanning
	ScanKeyInit(&key[0],
			Anum_pg_class_relnamespace,
			BTEqualStrategyNumber, F_OIDEQ,
			ObjectIdGetDatum(schemaOid));

	// Filter on "kind", only return tables
	ScanKeyInit(&key[1],
			Anum_pg_class_relkind,
			BTEqualStrategyNumber, F_CHAREQ,
			CharGetDatum(kind));

	scan = systable_beginscan(relation, InvalidOid, false, NULL, 2, key);
	while (HeapTupleIsValid(tuple = systable_getnext(scan)))
	{
		Form_pg_class  form = (Form_pg_class) GETSTRUCT(tuple);
		const char    *table_uri = pstr_uri_append_path_component(uri, NameStr(form->relname));

		oid = HeapTupleGetOid(tuple);

		jsonbuf_element_start_object(jp);

		jsonbuf_add_table_info(jp, oid, table_uri, form);

		jsonbuf_end_object(jp);
	}

	systable_endscan(scan);

	heap_close(relation, AccessShareLock);

	jsonbuf_end_array(jp);

}

void
tables_route_GET(struct restgres_request *req)
{
	struct jsonbuf *jp = req->jsonbuf;
	const char     *schemaname = evhttp_find_header(req->matchdict, "schemaname");
	HeapTuple       tup = SearchSysCache1(NAMESPACENAME, PointerGetDatum(schemaname));

	if (!HeapTupleIsValid(tup))
	{
		elog(ERROR, "lookup failed for schema '%s' in database '%s'", schemaname, evhttp_find_header(req->matchdict, "dbname"));
		req->status_code = 404;
		return;
	}

	add_json_content_type_header(req->reply_headers);
	jsonbuf_start_document(jp);
	jsonbuf_add_tables(jp, evhttp_uri_get_path(req->uri), HeapTupleGetOid(tup), RELKIND_RELATION);
	jsonbuf_end_document(jp);

	ReleaseSysCache(tup);
}
