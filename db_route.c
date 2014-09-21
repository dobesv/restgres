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
jsonbuf_add_database_info(struct jsonbuf *jp, Oid oid, Form_pg_database dbform)
{
	char       *datname_uri;
	HeapTuple	utup;
	HeapTuple	tstup;

	jsonbuf_member_cstring(jp, "name", dbform->datname.data);
	jsonbuf_member_cstring(jp, "oid", psprintf("%ud", oid));
	jsonbuf_member_cstring(jp, "encoding", pg_encoding_to_char(dbform->encoding));
	jsonbuf_member_cstring(jp, "collate", dbform->datcollate.data);
	jsonbuf_member_cstring(jp, "ctype", dbform->datctype.data);
	jsonbuf_member_bool(jp, "istemplate", dbform->datistemplate);
	jsonbuf_member_bool(jp, "allowconn", dbform->datallowconn);
	jsonbuf_member_int(jp, "connlimit", dbform->datconnlimit);

	jsonbuf_member_start_array(jp, "links");
	datname_uri = evhttp_encode_uri(dbform->datname.data);
	jsonbuf_element_link(jp, "self", DATABASE_METADATA_V1_TYPE, psprintf("/db/%s", datname_uri));
	free(datname_uri);

	utup = SearchSysCache1(AUTHOID, ObjectIdGetDatum(dbform->datdba));
	if (HeapTupleIsValid(utup))
	{
		char *owner_uri = evhttp_encode_uri(((Form_pg_authid) GETSTRUCT(utup))->rolname.data);
		ReleaseSysCache(utup);
		jsonbuf_element_link(jp, "owner", ROLE_METADATA_TYPE_V1, psprintf("/roles/%s", owner_uri));
		free(owner_uri);
	}

	tstup = SearchSysCache1(TABLESPACEOID, dbform->dattablespace);
	if(HeapTupleIsValid(tstup))
	{
		char *ts_uri = evhttp_encode_uri(((Form_pg_tablespace) GETSTRUCT(tstup))->spcname.data);
		ReleaseSysCache(tstup);
		jsonbuf_element_link(jp, "default_tablespace", ROLE_METADATA_TYPE_V1, psprintf("/roles/%s", ts_uri));
		free(ts_uri);
	}

	/* TODO Include ACL */

	jsonbuf_end_array(jp);

}

/* When we get here, the database we are asking about is the one we are connected to ... */
void
db_route_GET(struct restgres_request *req)
{
	struct jsonbuf *jp = req->jsonbuf;
	HeapTuple tup;
	Form_pg_database dbform;

	add_json_content_type_header(req->reply_headers);
	jsonbuf_start_document(jp);
	jsonbuf_member_start_object(jp, "database");

	tup = SearchSysCache1(DATABASEOID, ObjectIdGetDatum(MyDatabaseId));
	if (!HeapTupleIsValid(tup))
	{
		elog(ERROR, "cache lookup failed for database %u", MyDatabaseId);
		req->status_code = 500;
		return;
	}

	dbform = (Form_pg_database) GETSTRUCT(tup);

	jsonbuf_add_database_info(jp, MyDatabaseId, dbform);

	ReleaseSysCache(tup);

	jsonbuf_end_object(jp);
	jsonbuf_end_document(jp);
}
