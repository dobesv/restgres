/*
 * restgres_content_types.h
 *
 *  Created on: Sep 19, 2014
 *      Author: dobes
 */

#ifndef RESTGRES_CONTENT_TYPES_H_
#define RESTGRES_CONTENT_TYPES_H_

#define PG_MIME_JSON_V1(x) "application/vnd.postgresl-" #x "-v1+json;charset=utf8"
#define SERVER_METADATA_TYPE_V1 PG_MIME_JSON_V1(server)
#define DATABASE_LIST_TYPE_V1 PG_MIME_JSON_V1(databases)
#define DATABASE_METADATA_V1_TYPE PG_MIME_JSON_V1(database)
#define TABLESPACE_LIST_TYPE_V1 PG_MIME_JSON_V1(databases)
#define TABLESPACE_METADATA_TYPE_V1 PG_MIME_JSON_V1(database)
#define ROLE_LIST_TYPE_V1 PG_MIME_JSON_V1(roles)
#define ROLE_METADATA_TYPE_V1 PG_MIME_JSON_V1(role)
#define TABLE_LIST_TYPE_V1 PG_MIME_JSON_V1(tables)
#define TABLE_METADATA_TYPE_V1 PG_MIME_JSON_V1(table)
#define SCHEMA_LIST_TYPE_V1 PG_MIME_JSON_V1(schemas)
#define SCHEMA_METADATA_TYPE_V1 PG_MIME_JSON_V1(schema)
#define RESULTSET_TYPE_V1 PG_MIME_JSON_V1(resultset)
#define SQL_TYPE PG_MIME_JSON_V1(sql)
#define JSON_TYPE "application/json;charset=utf8"



#endif /* RESTGRES_CONTENT_TYPES_H_ */
