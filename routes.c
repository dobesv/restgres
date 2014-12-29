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

};

int num_routes = sizeof routes / sizeof routes[0];
