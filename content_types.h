/*
 * restgres_content_types.h
 *
 *  Created on: Sep 19, 2014
 *      Author: dobes
 */

#ifndef RESTGRES_CONTENT_TYPES_H_
#define RESTGRES_CONTENT_TYPES_H_

#define PG_MIME_JSON(x) "application/vnd.postgresl-" #x "+json;charset=utf8"
#define SERVER_METADATA_TYPE PG_MIME_JSON(server)
#define DATABASE_LIST_TYPE PG_MIME_JSON(databases)
#define DATABASE_METADATA_TYPE PG_MIME_JSON(database)
#define TABLESPACE_LIST_TYPE PG_MIME_JSON(databases)
#define TABLESPACE_METADATA_TYPE PG_MIME_JSON(database)
#define ROLE_LIST_TYPE PG_MIME_JSON(roles)
#define ROLE_METADATA_TYPE PG_MIME_JSON(role)
#define TABLE_LIST_TYPE PG_MIME_JSON(tables)
#define TABLE_METADATA_TYPE PG_MIME_JSON(table)
#define SCHEMA_LIST_TYPE PG_MIME_JSON(schemas)
#define SCHEMA_METADATA_TYPE PG_MIME_JSON(schema)
#define RESULTSET_TYPE PG_MIME_JSON(resultset)
#define SQL_TYPE PG_MIME_JSON(sql)
#define JSON_TYPE "application/json;charset=utf8"



#endif /* RESTGRES_CONTENT_TYPES_H_ */
