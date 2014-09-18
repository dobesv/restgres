/*
 * master.h
 *
 *  Created on: Sep 14, 2014
 *      Author: dobes
 */

#ifndef MASTER_H_
#define MASTER_H_

typedef enum
{
	RestgresBackend_Unused,
	RestgresBackend_Idle,
	RestgresBackend_Starting,
	RestgresBackend_Busy,
} RestgresBackendState;

struct restgres_backend
{
	RestgresBackendState state;
	pid_t pid;
	BackgroundWorkerHandle *bgworker_handle;
	struct bufferevent *bev;
	char *dbname;
	char *username;
	int last_used;
};

struct restgres_queued_request
{
	SIMPLEQ_ENTRY(restgres_queued_request) next;
	char *dbname;
	char *username;
	struct evbuffer *request;
	int reply_fd;
};

extern struct restgres_backend *backends;

extern int restgres_listen_port;
extern char *restgres_listen_addresses;
extern int restgres_max_connections;
extern int restgres_max_concurrency;

extern void restgres_main(Datum main_arg);


#endif /* MASTER_H_ */
