#include "unistd.h"

#include "postgres.h"

#include <fcntl.h>
#include <utils/elog.h>
#include <sys/queue.h>

#include <event2/keyvalq_struct.h>

#include "backend.h"
#include "util.h"
#include "routes.h"
#include "content_types.h"

struct restgres_route routes[] = {
		{
				"root.json",
				"/",
				EVHTTP_REQ_GET | EVHTTP_REQ_HEAD,
				JSON_TYPE,
				NULL,
				root_route_GET,
		},
		{
				"root.spec",
				"/",
				EVHTTP_REQ_GET | EVHTTP_REQ_HEAD,
				SERVER_METADATA_TYPE_V1,
				NULL,
				root_route_GET,
		},
		{
				"roles",
				"/roles",
				EVHTTP_REQ_GET | EVHTTP_REQ_HEAD,
				ROLE_LIST_TYPE_V1,
				NULL,
				roles_route_GET,
		},
		{
				"role",
				"/roles/{rolename}",
				EVHTTP_REQ_GET | EVHTTP_REQ_HEAD,
				ROLE_METADATA_TYPE_V1,
				NULL,
				role_route_GET,
		},
		{
				"databases",
				"/databases",
				EVHTTP_REQ_GET | EVHTTP_REQ_HEAD,
				DATABASE_LIST_TYPE_V1,
				NULL,
				databases_route_GET,
		},
		{
				"database",
				"/db/{dbname}",
				EVHTTP_REQ_GET | EVHTTP_REQ_HEAD,
				DATABASE_METADATA_TYPE_V1,
				NULL,
				db_route_GET,
		},
		{
				"schemas",
				"/db/{dbname}/schemas",
				EVHTTP_REQ_GET | EVHTTP_REQ_HEAD,
				SCHEMA_LIST_TYPE_V1,
				NULL,
				schemas_route_GET,
		},
		{
				"schema",
				"/db/{dbname}/schemas/{schemaname}",
				EVHTTP_REQ_GET | EVHTTP_REQ_HEAD,
				SCHEMA_METADATA_TYPE_V1,
				NULL,
				schema_route_GET,
		},
		{
				"tables",
				"/db/{dbname}/schemas/{schemaname}/tables",
				EVHTTP_REQ_GET | EVHTTP_REQ_HEAD,
				TABLE_LIST_TYPE_V1,
				NULL,
				tables_route_GET,
		},
		{
				"table",
				"/db/{dbname}/schemas/{schemaname}/tables/{tablename}",
				EVHTTP_REQ_GET | EVHTTP_REQ_HEAD,
				TABLE_METADATA_TYPE_V1,
				NULL,
				table_route_GET,
		},
		{
				"table_rows",
				"/db/{dbname}/schemas/{schemaname}/tables/{tablename}/rows",
				EVHTTP_REQ_GET | EVHTTP_REQ_HEAD,
				TABLE_LIST_TYPE_V1,
				NULL,
				table_rows_route_GET,
		},
		{
				"table_row",
				"/db/{dbname}/schemas/{schemaname}/tables/{tablename}/row/{pk}",
				EVHTTP_REQ_GET | EVHTTP_REQ_HEAD,
				TABLE_METADATA_TYPE_V1,
				NULL,
				table_row_route_GET,
		},

};

int num_routes = sizeof routes / sizeof routes[0];
