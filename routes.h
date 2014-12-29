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
	/* Route name, to identify this route in case we start to generate URLs using this route table */
	const char *name;

	/* URL pattern, using {varname} is a wildcard that stores the matched area into a matchdict key "varname" */
	const char *pattern;

	/* HTTP methods to match - a mask of EVHTTP_REQ_* values */
	enum evhttp_cmd_type cmd_type;

	/* Response content type - matched to the Accept header in the request and set as Content-Type in the response */
	const char *response_content_type;

	/* Request content type - matched to the Content-Type header in the request */
	const char *request_content_type;

	/* Handler function to actually fill in the response */
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

void
jsonbuf_add_databases(struct jsonbuf *jp);
void
jsonbuf_add_roles(struct jsonbuf *jp);

/* Handler function declarations */
void
root_route_GET(struct restgres_request *req);
void
databases_route_GET(struct restgres_request *req);
void
db_route_GET(struct restgres_request *req);
void
roles_route_GET(struct restgres_request *req);
void
role_route_GET(struct restgres_request *req);

#endif /* ROUTES_H_ */
