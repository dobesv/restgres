/*
 * restgres_evutil.h
 *
 *  Created on: Sep 14, 2014
 *      Author: dobes
 */

#ifndef RESTGRES_UTIL_H_
#define RESTGRES_UTIL_H_

#include <event2/util.h>
#include <event2/http.h>
#include <event2/buffer.h>

const char *
cmd_type_method(enum evhttp_cmd_type cmd_type);


const char *
remove_prefix(const char *name, const char *path);

void
escape_json(StringInfo buf, const char *str);

/* Add a cstring to a buffer */
void
evbuffer_add_cstring(struct evbuffer *buf, const char *str);

/* Add CRLF to a buffer */
void
evbuffer_add_crlf(struct evbuffer *buf);

/*
 * Escape quotes in the string, if there are any.  If not, returns the original string.  Any
 * new string returned is allocated using palloc, which means it will be freed at the end of the request
 * processing.
 */
const char *
_escape_quotes(const char *input, char q);

/* Escape double quotes; see _escape_quotes */
const char *
_escape_double_quotes(const char *input);

/**
 * Get a evhttp_cmd_type for a char *
 */
enum evhttp_cmd_type
method_cmd_type(char *method);

/**
 * Get a char * for a evhttp_cmd_type.
 */
const char *
cmd_type_method(enum evhttp_cmd_type cmd_type);

/*
 * Append a buffer to a buffer as a netstring.
 *
 * If drain_src is true the source buffer is drained and some copying might
 * be avoided.
 */
void
evbuffer_add_netstring_buffer(struct evbuffer *buf, struct evbuffer *string, bool drain_src);

/*
 * Append a C string to an evbuffer as a netstring
 */
void
evbuffer_add_netstring_cstring(struct evbuffer *buf, const char *string);

/* Add headers to the given output buffer, separated using CRLF */
void
evbuffer_add_headers(struct evbuffer *reply_buffer, struct evkeyvalq *headers);

/*
 * Read a netstring from the input.  The input must contain a complete
 * netstring.
 *
 * If the input doesn't contain a whole netstring, this returns the number
 * of additional bytes needed if the length of the netstring was available,
 * or -1 if the length of the netstring was not availabe.
 *
 * If the netstring is fully available, this copies it into the provided buffer.
 */
ssize_t
evbuffer_remove_netstring_buffer(struct evbuffer *input, struct evbuffer *output);

/*
 * Read a netstring from the input.  The input must contain a complete
 * netstring.  Returns a newly allocated cstring, which the caller must
 * free using free().  If the input doesn't contain the whole
 * netstring, return NULL.
 */
char *
evbuffer_remove_netstring_cstring(struct evbuffer *input);

/*
 * Create a socket and optionally set some flags on it
 */
evutil_socket_t
socket_with_flags(int domain, int type, int protocol);

/*
 * Create a socket and bind() it to the given address
 */
evutil_socket_t
bound_socket(struct evutil_addrinfo *ai, int reuse);

/*
 * Check whether the input starts with the given path component; returns the remainder of the string if so
 * Return NULL if the prefix doesn't match.
 */
const char *
remove_prefix(const char *prefix, const char *input);

/*
 * NULL-safe string equality check.  If both strings are NULL, returns true.  If only
 * one is NULL, returns false.  If both are not NULL, streql returns strcmp(a,b) == 0.
 */
bool
streql(const char *a, const char *b);

/*
 * Get the uid, gid, and pid of the connected peer.
 *
 * All the out parameters must be non-NULL.
 *
 * Returns -1 on failure or 0 on success; errno should be set on failure.
 */
int
getpeerpideid(int sock, pid_t *pid, uid_t *uid, gid_t *gid);


#endif /* RESTGRES_EVUTIL_H_ */