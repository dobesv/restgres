/*
 * routes.h
 *
 *  Created on: Sep 17, 2014
 *      Author: dobes
 */

#ifndef ROUTES_H_
#define ROUTES_H_

struct restgres_request
{
	int status_code;
	pgsocket reply_fd;
	const char *http_ver;
	enum evhttp_cmd_type cmd_type;
	struct evhttp_uri *uri;
	struct evkeyvalq *headers;
	struct evkeyvalq *query_params;
	struct evbuffer *body_buffer;
	struct evkeyvalq *reply_headers;
	struct evbuffer *reply_buffer;
	struct evkeyvalq *matchdict;
	struct jsonbuf *jsonbuf;
};
typedef void (*restgres_request_handler)(struct restgres_request *req);

struct restgres_route
{
	const char *name;
	const char *pattern;
	enum evhttp_cmd_type cmd_type;
	restgres_request_handler handler;
};

extern struct restgres_route routes[];
extern int num_routes;

int
match_route(struct restgres_route *route, struct restgres_request *req);

struct restgres_route *
find_best_route(struct restgres_request *req);

void
parse_route_uri_pattern(const char *path_input, const char *path_pattern, struct evkeyvalq *matchdict);

/* Handler function declarations */
void
root_route_GET(struct restgres_request *req);

#endif /* ROUTES_H_ */
