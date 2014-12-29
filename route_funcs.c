/*
 * route_funcs.c
 *
 *  Created on: Dec 28, 2014
 *      Author: dobes
 */

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


static int
match_route_uri_pattern(const char *path_input, const char *path_pattern)
{
	while(*path_input && *path_pattern)
	{
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
			if(*path_pattern != *path_input)
				return -1;
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
	char  keybuf[32];
	char *kp;
	char  valbuf[512];
	char *vp;
	char  looking_for;
	char *val_decoded;
	while(*path_input && *path_pattern)
	{
		if(*path_pattern == '{')
		{
			path_pattern++;
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
				{
					val_decoded = evhttp_uridecode(valbuf, 1, NULL);
					evhttp_add_header(matchdict, keybuf, val_decoded);
					free(val_decoded);
				}
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

	/* Check method - req->cmd_type should have just one bit set but route->cmd_type is a mask */
	if((req->cmd_type & route->cmd_type) == 0)
		return -1;

	/* Now check to make sure the path matches the path pattern */
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
