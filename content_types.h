/*
 * restgres_content_types.h
 *
 *  Created on: Sep 19, 2014
 *      Author: dobes
 */

#ifndef RESTGRES_CONTENT_TYPES_H_
#define RESTGRES_CONTENT_TYPES_H_

#define PG_MIME_JSON_V1(x) "application/vnd.postgresl-" #x "-v1+json;charset=utf8"
#define PG_DDL_JSON_V1(x) "application/vnd.postgresl-" #x "-v1+sql;charset=utf8"
#define SERVER_METADATA_TYPE_V1 PG_MIME_JSON_V1(server)
#define TYPE_LIST_TYPE_V1 PG_MIME_JSON_V1(types)
#define TYPE_METADATA_TYPE_V1 PG_MIME_JSON_V1(type)
#define DATABASE_LIST_TYPE_V1 PG_MIME_JSON_V1(databases)
#define DATABASE_METADATA_TYPE_V1 PG_MIME_JSON_V1(database)
#define TABLESPACE_LIST_TYPE_V1 PG_MIME_JSON_V1(databases)
#define TABLESPACE_METADATA_TYPE_V1 PG_MIME_JSON_V1(database)
#define SCHEMA_LIST_TYPE_V1 PG_MIME_JSON_V1(schemas)
#define SCHEMA_METADATA_TYPE_V1 PG_MIME_JSON_V1(schema)
#define TABLE_LIST_TYPE_V1 PG_MIME_JSON_V1(tables)
#define TABLE_METADATA_TYPE_V1 PG_MIME_JSON_V1(table)
#define ROLE_LIST_TYPE_V1 PG_MIME_JSON_V1(roles)
#define ROLE_METADATA_TYPE_V1 PG_MIME_JSON_V1(role)
#define TABLE_COLUMN_LIST_TYPE_V1 PG_MIME_JSON_V1(columns)
#define TABLE_COLUMN_METADATA_TYPE_V1 PG_MIME_JSON_V1(column)
#define TABLE_ROW_LIST_TYPE_V1 PG_MIME_JSON_V1(rows)
#define TABLE_ROW_METADATA_TYPE_V1 PG_MIME_JSON_V1(row)
#define TABLE_ROW_DATA_TYPE_V1 PG_MIME_JSON_V1(row-data)
#define RESULTSET_TYPE_V1 PG_MIME_JSON_V1(resultset)
#define SQL_TYPE "application/vnd.postgresl-sql+sql;charset=utf8"
#define JSON_TYPE "application/json;charset=utf8"



#endif /* RESTGRES_CONTENT_TYPES_H_ */
