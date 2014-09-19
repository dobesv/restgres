#define sigjmp_buf jmp_buf
#include "setjmp.h"
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

#include <event2/http.h>
#include <event2/util.h>
#include <event2/keyvalq_struct.h>

#include "routes.h"
#include "jsonbuf.h"
#include "util.h"

void
root_route_GET(struct restgres_request *req)
{
	int ret;
	HeapTuple spi_tuple;
	SPITupleTable *spi_tuptable = SPI_tuptable;
	TupleDesc spi_tupdesc = spi_tuptable->tupdesc;
	char *datname;
	char *datname_uri;
	char *url;
	struct jsonbuf *jp = req->jsonbuf;
	add_json_content_type_header(req->reply_headers);
	jsonbuf_start_document(jp);
	jsonbuf_member_cstring(jp, "version", PG_VERSION_STR);

	jsonbuf_member_start_array(jp, "databases");


	ret = SPI_execute("SELECT datname FROM pg_database WHERE datistemplate = false;", true, 0);
	if (ret != SPI_OK_SELECT)
		elog(FATAL, "SPI_execute failed: error code %d", ret);
	for (int i = 0; i < SPI_processed; i++)
	{
		spi_tuptable = SPI_tuptable;
		spi_tupdesc = spi_tuptable->tupdesc;
		spi_tuple = SPI_tuptable->vals[i];
		datname = SPI_getvalue(spi_tuple, spi_tupdesc, 1);
		datname_uri = evhttp_encode_uri(datname);
		url = psprintf("/databases/%s", datname_uri);

		jsonbuf_member_start_object(jp, datname);
		/* TODO Include some interesting information about the database */
		jsonbuf_member_cstring(jp, "name", datname);
		jsonbuf_member_cstring(jp, "url", url);
		jsonbuf_end_object(jp);

		free(datname_uri);
		pfree(url);
	}

	jsonbuf_end_array(jp);

	jsonbuf_end_document(jp);


}
