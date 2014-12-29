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
jsonbuf_add_schema_info(struct jsonbuf *jp, Oid oid, const char *uri, Form_pg_namespace form);


void
jsonbuf_add_schema_info(struct jsonbuf *jp, Oid oid, const char *uri, Form_pg_namespace form)
{
	HeapTuple	utup;

	jsonbuf_member_cstring(jp, "name", NameStr(form->nspname));
	jsonbuf_member_cstring(jp, "oid", psprintf("%u", oid));

	jsonbuf_member_start_array(jp, "links");
	jsonbuf_element_link(jp, "self", SCHEMA_METADATA_TYPE_V1, uri);

	utup = SearchSysCache1(AUTHOID, ObjectIdGetDatum(form->nspowner));
	if (HeapTupleIsValid(utup))
	{
		char *owner_uri = evhttp_encode_uri(((Form_pg_authid) GETSTRUCT(utup))->rolname.data);
		ReleaseSysCache(utup);
		jsonbuf_element_link(jp, "owner", ROLE_METADATA_TYPE_V1, psprintf("/roles/%s", owner_uri));
		free(owner_uri);
	}

	jsonbuf_end_array(jp);

}

/* When we get here, the schema we are asking about is the one we are connected to ... */
void
schema_route_GET(struct restgres_request *req)
{
	struct jsonbuf *jp = req->jsonbuf;
	const char *name = evhttp_find_header(req->matchdict, "schemaname");
	HeapTuple tup;
	Form_pg_namespace form;
	if(!(name && name[0]))
	{
		req->status_code = 404;
		return;
	}

	add_json_content_type_header(req->reply_headers);
	jsonbuf_start_document(jp);
	jsonbuf_member_start_object(jp, "schema");

	tup = SearchSysCache1(NAMESPACENAME, PointerGetDatum(name));
	if (!HeapTupleIsValid(tup))
	{
		elog(ERROR, "lookup failed for schema '%s' in database '%s'", name, evhttp_find_header(req->matchdict, "dbname"));
		req->status_code = 404;
		return;
	}

	form = (Form_pg_namespace) GETSTRUCT(tup);

	jsonbuf_add_schema_info(jp, HeapTupleGetOid(tup), evhttp_uri_get_path(req->uri), form);

	ReleaseSysCache(tup);

	jsonbuf_end_object(jp);
	jsonbuf_end_document(jp);
}
