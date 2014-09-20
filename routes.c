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
				DATABASE_LIST_TYPE_V1,
				NULL,
				db_route_GET,
		}
};

int num_routes = sizeof routes / sizeof routes[0];

static int
match_route_uri_pattern(const char *path_input, const char *path_pattern)
{
	while(*path_input && *path_pattern)
	{
		if(*path_pattern != *path_input)
			return -1;
		if(*path_pattern == '{')
		{
			char looking_for;
			while(*path_pattern && *path_pattern != '}')
				path_pattern++;
			if(*path_pattern == '}')
			{
				path_pattern++;

				/* If we reached the end of the string, consider '/' the next separator */
				looking_for = *path_pattern;
				if(!looking_for)
					looking_for='/';
				while(*path_input && *path_input != looking_for)
					path_input++;
			}
		}
		else
		{
			path_pattern++;
			path_input++;
		}
	}
	/* If we did not match the entire input, then the route doesn't match */
	if(*path_input || *path_pattern)
		return -1;

	return 1;
}

void
parse_route_uri_pattern(const char *path_input, const char *path_pattern, struct evkeyvalq *matchdict)
{
	char keybuf[32];
	char *kp;
	char valbuf[512];
	char *vp;
	while(*path_input && *path_pattern)
	{
		if(*path_pattern == '{')
		{
			char looking_for;

			kp = keybuf;
			while(*path_pattern && *path_pattern != '}')
			{
				int len = (kp - keybuf);
				if(len+1 >= sizeof keybuf)
				{
					*kp = 0;
					elog(ERROR, "Path pattern has varname with >= %d characters: %.*s", (int)sizeof keybuf, (int)len, kp);
					return;
				}
				*kp = *path_pattern;
				kp++;
				path_pattern++;
			}
			*kp = 0;
			if(*path_pattern == '}')
			{
				path_pattern++;

				/* If we reached the end of the string, consider '/' the next separator */
				looking_for = *path_pattern;
				if(!looking_for)
					looking_for='/';
				vp = valbuf;
				while(*path_input && *path_input != looking_for)
				{
					int len = (vp - valbuf);
					if(len+1 >= sizeof valbuf)
					{
						elog(ERROR, "Path URI has component with >= %d characters: %.*s", (int)sizeof valbuf, (int)len, valbuf);
						return;
					}
					*vp = *path_input;
					vp++;
					path_input++;
				}
				*vp = 0;
				/* Save the value if the key is non-empty */
				if(keybuf[0])
					evhttp_add_header(matchdict, keybuf, valbuf);
			}

		}
		else
		{
			path_pattern++;
			path_input++;
		}
	}
}

int
match_route(struct restgres_route *route, struct restgres_request *req)
{
	int score;

	/* Check method */
	if((req->cmd_type & route->cmd_type) == 0)
		return -1;

	score = match_route_uri_pattern(evhttp_uri_get_path(req->uri), route->pattern);
	if(score < 0)
		return -1;

	/* TODO Check the accept and content-type headers */

	return score;
}

struct restgres_route *
find_best_route(struct restgres_request *req)
{
	struct restgres_route *best_route=NULL;
	int best_score = 0;
	int i;
	for(i=0; i < num_routes; i++)
	{
		struct restgres_route *route = &routes[i];
		int score = match_route(route, req);
		if(score > best_score)
		{
			best_route = route;
			best_score = score;
		}
	}
	return best_route;
}
