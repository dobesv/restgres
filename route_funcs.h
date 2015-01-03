/*
 * route_funcs.h
 *
 *  Created on: Dec 29, 2014
 *      Author: dobes
 */

#ifndef ROUTE_FUNCS_H_
#define ROUTE_FUNCS_H_

int
match_route(struct restgres_route *route, struct restgres_request *req);

struct restgres_route *
find_best_route(struct restgres_request *req);

void
parse_route_uri_pattern(const char *path_input, const char *path_pattern, struct evkeyvalq *matchdict);

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
void
schemas_route_GET(struct restgres_request *req);
void
schema_route_GET(struct restgres_request *req);
void
tables_route_GET(struct restgres_request *req);
void
table_route_GET(struct restgres_request *req);
void
table_rows_route_GET(struct restgres_request *req);
void
table_row_route_GET(struct restgres_request *req);

#endif /* ROUTE_FUNCS_H_ */
