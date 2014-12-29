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
jsonbuf_add_role_info(struct jsonbuf *jp, Oid oid, Form_pg_authid form);


void
jsonbuf_add_role_info(struct jsonbuf *jp, Oid oid, Form_pg_authid form)
{
	char       *datname_uri = evhttp_encode_uri(NameStr(form->rolname));

	jsonbuf_member_cstring(jp, "name", NameStr(form->rolname));
	jsonbuf_member_cstring(jp, "oid", psprintf("%u", oid));
	jsonbuf_member_bool(jp, "super", form->rolsuper);
	jsonbuf_member_bool(jp, "inherit", form->rolinherit);
	jsonbuf_member_bool(jp, "createrole", form->rolcreaterole);
	jsonbuf_member_bool(jp, "createdb", form->rolcreatedb);
	jsonbuf_member_bool(jp, "catupdate", form->rolcatupdate);
	jsonbuf_member_bool(jp, "canlogin", form->rolcanlogin);
	jsonbuf_member_bool(jp, "replication", form->rolreplication);
	jsonbuf_member_int(jp, "connlimit", form->rolconnlimit);

	jsonbuf_member_start_array(jp, "links");
	jsonbuf_element_link(jp, "self", ROLE_METADATA_TYPE_V1, psprintf("/roles/%s", datname_uri));

	free(datname_uri);

	jsonbuf_end_array(jp);

}

/* When we get here, the role we are asking about is the one we are connected to ... */
void
role_route_GET(struct restgres_request *req)
{
	struct jsonbuf *jp = req->jsonbuf;
	const char *rolename = evhttp_find_header(req->matchdict, "rolename");
	HeapTuple tup;
	Form_pg_authid form;
	if(!(rolename && rolename[0]))
	{
		req->status_code = 404;
		return;
	}

	add_json_content_type_header(req->reply_headers);
	jsonbuf_start_document(jp);
	jsonbuf_member_start_object(jp, "role");

	tup = SearchSysCache1(AUTHNAME, PointerGetDatum(rolename));
	if (!HeapTupleIsValid(tup))
	{
		elog(ERROR, "lookup failed for role '%s'", rolename);
		req->status_code = 404;
		return;
	}

	form = (Form_pg_authid) GETSTRUCT(tup);

	jsonbuf_add_role_info(jp, HeapTupleGetOid(tup), form);

	ReleaseSysCache(tup);

	jsonbuf_end_object(jp);
	jsonbuf_end_document(jp);
}
