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
jsonbuf_add_databases(struct jsonbuf *jp)
{
	char *datname_uri;
	Relation	relation;
	SysScanDesc scan;
	HeapTuple	tuple;
	HeapTuple	utup;
	HeapTuple	tstup;
	Oid			dbOid;


	jsonbuf_member_start_array(jp, "databases");

	relation = heap_open(DatabaseRelationId, AccessShareLock);

	scan = systable_beginscan(relation, InvalidOid, false,
							  NULL, 0, NULL);
	while (HeapTupleIsValid(tuple = systable_getnext(scan)))
	{
		Form_pg_database dbform = (Form_pg_database) GETSTRUCT(tuple);

		jsonbuf_element_start_object(jp);

#if 0
		NameData	datname;		/* database name */
		Oid			datdba;			/* owner of database */
		int32		encoding;		/* character encoding */
		NameData	datcollate;		/* LC_COLLATE setting */
		NameData	datctype;		/* LC_CTYPE setting */
		bool		datistemplate;	/* allowed as CREATE DATABASE template? */
		bool		datallowconn;	/* new connections allowed? */
		int32		datconnlimit;	/* max connections allowed (-1=no limit) */
		Oid			datlastsysoid;	/* highest OID to consider a system OID */
		TransactionId datfrozenxid; /* all Xids < this are frozen in this DB */
		TransactionId datminmxid;	/* all multixacts in the DB are >= this */
		Oid			dattablespace;	/* default table space for this DB */
#endif
		dbOid = HeapTupleGetOid(tuple);
		jsonbuf_member_cstring(jp, "name", dbform->datname.data);
		jsonbuf_member_cstring(jp, "oid", psprintf("%ud", dbOid)); /* String so we don't have to change types if this exceeds the range of int */
		jsonbuf_member_cstring(jp, "encoding", pg_encoding_to_char(dbform->encoding));
		jsonbuf_member_cstring(jp, "collate", dbform->datcollate.data);
		jsonbuf_member_cstring(jp, "ctype", dbform->datctype.data);
		jsonbuf_member_bool(jp, "istemplate", dbform->datistemplate);
		jsonbuf_member_bool(jp, "allowconn", dbform->datallowconn);
		jsonbuf_member_int(jp, "connlimit", dbform->datconnlimit);

		jsonbuf_member_start_array(jp, "links");
		datname_uri = evhttp_encode_uri(dbform->datname.data);
		jsonbuf_element_link(jp, "self", DATABASE_METADATA_TYPE, psprintf("/databases/%s", datname_uri));
		free(datname_uri);

		utup = SearchSysCache1(AUTHOID, ObjectIdGetDatum(dbform->datdba));
		if (HeapTupleIsValid(utup))
		{
			char *owner_uri = evhttp_encode_uri(((Form_pg_authid) GETSTRUCT(utup))->rolname.data);
			ReleaseSysCache(utup);
			jsonbuf_element_link(jp, "owner", ROLE_METADATA_TYPE, psprintf("/roles/%s", owner_uri));
			free(owner_uri);
		}

		tstup = SearchSysCache1(TABLESPACEOID, dbform->dattablespace);
		if(HeapTupleIsValid(tstup))
		{
			char *ts_uri = evhttp_encode_uri(((Form_pg_tablespace) GETSTRUCT(tstup))->spcname.data);
			ReleaseSysCache(tstup);
			jsonbuf_element_link(jp, "default_tablespace", ROLE_METADATA_TYPE, psprintf("/roles/%s", ts_uri));
			free(ts_uri);
		}

		jsonbuf_end_array(jp);

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
