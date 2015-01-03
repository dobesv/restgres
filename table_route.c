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
#include "catalog/pg_type.h"
#include "catalog/indexing.h"
#include "utils/fmgroids.h"
#include "access/htup_details.h"
#include "storage/lmgr.h"
#include "mb/pg_wchar.h"
#include "utils/syscache.h"
#include "utils/tqual.h"

#include <event2/http.h>
#include <event2/util.h>
#include <event2/keyvalq_struct.h>

#include "routes.h"
#include "jsonbuf.h"
#include "util.h"
#include "content_types.h"

void
jsonbuf_add_table_info(struct jsonbuf *jp, Oid oid, const char *uri, Form_pg_class form);

void
jsonbuf_add_column_info(struct jsonbuf *jp, Oid oid, const char *uri, Form_pg_attribute form);

void
jsonbuf_add_column_info(struct jsonbuf *jp, Oid oid, const char *uri, Form_pg_attribute form)
{
	char *typeUri;
	HeapTuple typeTup = NULL;
	Form_pg_type typeForm = NULL;

	jsonbuf_member_cstring(jp, "name", NameStr(form->attname));

	if(OidIsValid(form->atttypid) && HeapTupleIsValid(typeTup = SearchSysCache1(TYPEOID, ObjectIdGetDatum(form->atttypid)))) {
		typeForm = (Form_pg_type) GETSTRUCT(typeTup);
		jsonbuf_member_cstring(jp, "type", NameStr(typeForm->typname));
	}

	jsonbuf_member_bool(jp, "notnull", form->attnotnull);
	if(form->attlen > 0)
		jsonbuf_member_int(jp, "length", form->attlen);

	jsonbuf_member_start_array(jp, "links");
	jsonbuf_element_link(jp, "self", TABLE_COLUMN_METADATA_TYPE_V1, uri);
	if(typeForm != NULL) {
		typeUri = pstr_uri_append_path_component("/types", NameStr(typeForm->typname));
		jsonbuf_element_link(jp, "type", TYPE_METADATA_TYPE_V1, typeUri);
		pfree(typeUri);
		ReleaseSysCache(typeTup);
	}

	jsonbuf_end_array(jp);
}

void
jsonbuf_add_table_info(struct jsonbuf *jp, Oid oid, const char *uri, Form_pg_class form)
{
	Relation	arel;
	ScanKeyData akey[2];
	SysScanDesc ascan;
	HeapTuple	atup;
	Form_pg_attribute attForm;
	char *columnUri;
	char *columnsUri;
	char *rowsUri;

	columnsUri = psprintf("%s/columns", uri);
	rowsUri = psprintf("%s/rows", uri);

	jsonbuf_member_cstring(jp, "name", NameStr(form->relname));
	jsonbuf_member_cstring(jp, "oid", psprintf("%u", oid));

	jsonbuf_member_int(jp, "pages", form->relpages);

	// TODO reltuples, relallvisible, reltoastrelid

	jsonbuf_member_bool(jp, "hasindex", form->relhasindex);
	jsonbuf_member_bool(jp, "isshared", form->relisshared);

	switch(form->relpersistence)
	{
	case RELPERSISTENCE_PERMANENT: jsonbuf_member_cstring(jp, "persistence", "permanent"); break;
	case RELPERSISTENCE_UNLOGGED: jsonbuf_member_cstring(jp, "persistence", "unlogged"); break;
	case RELPERSISTENCE_TEMP: jsonbuf_member_cstring(jp, "persistence", "temp"); break;
	default: break;
	}

	switch(form->relkind)
	{
	case RELKIND_RELATION: jsonbuf_member_cstring(jp, "kind", "relation"); break;
	case RELKIND_INDEX: jsonbuf_member_cstring(jp, "kind", "index"); break;
	case RELKIND_SEQUENCE: jsonbuf_member_cstring(jp, "kind", "sequence"); break;
	case RELKIND_TOASTVALUE: jsonbuf_member_cstring(jp, "kind", "toastvalue"); break;
	case RELKIND_VIEW: jsonbuf_member_cstring(jp, "kind", "view"); break;
	case RELKIND_COMPOSITE_TYPE: jsonbuf_member_cstring(jp, "kind", "composite_type"); break;
	case RELKIND_FOREIGN_TABLE: jsonbuf_member_cstring(jp, "kind", "foreign_table"); break;
	case RELKIND_MATVIEW: jsonbuf_member_cstring(jp, "kind", "matview"); break;
	default: break;
	}

	jsonbuf_member_start_array(jp, "columns");


	arel = heap_open(AttributeRelationId, AccessShareLock);

	ScanKeyInit(&akey[0],
				Anum_pg_attribute_attrelid,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(oid));
	ScanKeyInit(&akey[1],
			    Anum_pg_attribute_attnum,
			    BTGreaterStrategyNumber, F_INT2GT,
			    Int16GetDatum(0));

	ascan = systable_beginscan(arel, AttributeRelidNumIndexId, true, NULL, 2, akey);

	while (HeapTupleIsValid(atup = systable_getnext(ascan)))
	{
		attForm = (Form_pg_attribute) GETSTRUCT(atup);
		columnUri = pstr_uri_append_path_component(columnsUri, NameStr(attForm->attname));
		jsonbuf_element_start_object(jp);
		jsonbuf_add_column_info(jp, HeapTupleGetOid(atup), columnUri, attForm);
		jsonbuf_end_object(jp);
		pfree(columnUri);
	}

	systable_endscan(ascan);
	heap_close(arel, AccessShareLock);

	jsonbuf_end_array(jp);

	jsonbuf_member_start_array(jp, "links");
	jsonbuf_element_link(jp, "self", TABLE_METADATA_TYPE_V1, uri);
	if(OidIsValid(form->reltype))
		jsonbuf_element_link(jp, "columns", TABLE_COLUMN_LIST_TYPE_V1, columnsUri);
	jsonbuf_element_link(jp, "rows", TABLE_ROW_LIST_TYPE_V1, rowsUri);
	jsonbuf_element_role_link(jp, "owner", form->relowner);
	jsonbuf_add_tablespace_link(jp, "tablespace", form->reltablespace);

	jsonbuf_end_array(jp);

	// TODO reltype, reloftype, relam, relfilename, relnatts

	jsonbuf_member_int(jp, "checks", (int)form->relchecks);
	jsonbuf_member_bool(jp, "hasoids", form->relhasoids);
	jsonbuf_member_bool(jp, "haspkey", form->relhaspkey);
	jsonbuf_member_bool(jp, "hasrules", form->relhasrules);
	jsonbuf_member_bool(jp, "hastriggers", form->relhastriggers);
	jsonbuf_member_bool(jp, "hassubclass", form->relhassubclass);
	jsonbuf_member_bool(jp, "ispopulated", form->relispopulated);

	switch(form->relreplident)
	{
	case REPLICA_IDENTITY_DEFAULT: jsonbuf_member_cstring(jp, "replident", "default"); break;
	case REPLICA_IDENTITY_NOTHING: jsonbuf_member_cstring(jp, "replident", "nothing"); break;
	case REPLICA_IDENTITY_FULL: jsonbuf_member_cstring(jp, "replident", "full"); break;
	case REPLICA_IDENTITY_INDEX: jsonbuf_member_cstring(jp, "replident", "index"); break;
	default: break;
	}

	jsonbuf_member_int(jp, "frozenxid", form->relfrozenxid);
	jsonbuf_member_int(jp, "minmxid", form->relminmxid);

	// TODO acl's ?

	pfree(columnsUri);

}

void
table_route_GET(struct restgres_request *req)
{
	struct jsonbuf *jp = req->jsonbuf;
	const char     *tablename = evhttp_find_header(req->matchdict, "tablename");
	const char     *schemaname = evhttp_find_header(req->matchdict, "schemaname");
	Oid             schemaOid = GetSysCacheOid1(NAMESPACENAME, PointerGetDatum(schemaname));
	HeapTuple       tabletup;
	Form_pg_class   form;

	if (!OidIsValid(schemaOid))
	{
		elog(ERROR, "lookup failed for schema '%s' in database '%s'", schemaname, evhttp_find_header(req->matchdict, "dbname"));
		req->status_code = 404;
		return;
	}

	tabletup = SearchSysCache2(RELNAMENSP, PointerGetDatum(tablename), ObjectIdGetDatum(schemaOid));
	if (!HeapTupleIsValid(tabletup))
	{
		elog(ERROR, "lookup failed for table '%s' in schema '%s' in database '%s'", tablename, schemaname, evhttp_find_header(req->matchdict, "dbname"));
		req->status_code = 404;
		return;
	}
	form = (Form_pg_class) GETSTRUCT(tabletup);

	add_json_content_type_header(req->reply_headers);
	jsonbuf_start_document(jp);
	jsonbuf_member_start_object(jp, "table");

	jsonbuf_add_table_info(jp, HeapTupleGetOid(tabletup), evhttp_uri_get_path(req->uri), form);

	jsonbuf_end_object(jp);
	jsonbuf_end_document(jp);

	ReleaseSysCache(tabletup);
}
