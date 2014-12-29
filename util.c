
#include "setjmp.h"
#include "unistd.h"

#include "postgres.h"

#include <fcntl.h>
#include <utils/elog.h>

#include <sys/param.h>
#include <sys/socket.h>
#ifdef HAVE_SYS_UN_H
#include <sys/un.h>
#endif
#ifdef HAVE_UCRED_H
#include <ucred.h>
#endif
#ifdef HAVE_SYS_UCRED_H
#include <sys/ucred.h>
#endif
#include <sys/queue.h>

#include <event2/keyvalq_struct.h>

#include "lib/stringinfo.h"

#include "util.h"

static ssize_t
evbuffer_netstring_available(struct evbuffer *input, ssize_t *offset_out, ssize_t *length_out);

/* Faster version of evutil_make_socket_nonblocking for internal use.
 *
 * Requires that no F_SETFL flags were previously set on the fd.
 */
static int
evutil_fast_socket_nonblocking(evutil_socket_t fd)
{
#ifdef _WIN32
	return evutil_make_socket_nonblocking(fd);
#else
	if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1) {
		elog(WARNING, "fcntl(%d, F_SETFL)", fd);
		return -1;
	}
	return 0;
#endif
}

/* Faster version of evutil_make_socket_closeonexec for internal use.
 *
 * Requires that no F_SETFD flags were previously set on the fd.
 */
static int
evutil_fast_socket_closeonexec(evutil_socket_t fd)
{
#if !defined(_WIN32) && defined(EVENT__HAVE_SETFD)
	if (fcntl(fd, F_SETFD, FD_CLOEXEC) == -1) {
		elog(WARNING, "fcntl(%d, F_SETFD)", fd);
		return -1;
	}
#endif
	return 0;
}

/* Internal wrapper around 'socket' to provide Linux-style support for
 * syscall-saving methods where available.
 *
 * In addition to regular socket behavior, you can use a bitwise or to set the
 * flags EVUTIL_SOCK_NONBLOCK and EVUTIL_SOCK_CLOEXEC in the 'type' argument,
 * to make the socket nonblocking or close-on-exec with as few syscalls as
 * possible.
 */
evutil_socket_t
socket_with_flags(int domain, int type, int protocol)
{
	evutil_socket_t r;
#if defined(SOCK_NONBLOCK) && defined(SOCK_CLOEXEC)
	r = socket(domain, type, protocol);
	if (r >= 0)
		return r;
	else if ((type & (SOCK_NONBLOCK|SOCK_CLOEXEC)) == 0)
		return -1;
#endif
#define SOCKET_TYPE_MASK (~(SOCK_NONBLOCK|SOCK_CLOEXEC))
	r = socket(domain, type & SOCKET_TYPE_MASK, protocol);
	if (r < 0)
		return -1;
	if (type & SOCK_NONBLOCK) {
		if (evutil_fast_socket_nonblocking(r) < 0) {
			evutil_closesocket(r);
			return -1;
		}
	}
	if (type & SOCK_CLOEXEC) {
		if (evutil_fast_socket_closeonexec(r) < 0) {
			evutil_closesocket(r);
			return -1;
		}
	}
	return r;
}

/*
 * Escape quotes in the string, if there are any.  If not, returns the original string.  Any
 * new string returned is allocated using palloc, which means it will be freed at the end of the request
 * processing.
 */
const char *
_escape_quotes(const char *input, char q)
{
	int len = 1;
	int escapes = 0;
	char *output;
	const char *a;
	char *b;

	if (input == NULL)
		return NULL;
	for (const char *p = input; *p; p++)
	{
		if (*p == q || *p == '\\')
		{
			len++;
			escapes++;
		}
		len++;
	}

	if (escapes == 0)
		return input;

	b = output = palloc(len+1);
	for (a = input; *a; a++)
	{
		if (*a == q || *a == '\\')
		{
			*b = '\\';
			b++;
		}
		*b = *a;
		b++;
	}
	*b = 0;
	return output;
}

const char *
_escape_double_quotes(const char *input)
{
	return _escape_quotes(input, '"');
}

/**
 * Add a null-terminated string to the buffer.
 */
void
evbuffer_add_cstring(struct evbuffer *buf, const char *str)
{
	evbuffer_add(buf, str, strlen(str));
}

/**
 * Add a single character to the buffer.
 */
void
evbuffer_add_char(struct evbuffer *buf, char ch)
{
	evbuffer_add(buf, &ch, 1);
}

/* Add CRLF to a buffer */
void
evbuffer_add_crlf(struct evbuffer *buf)
{
	evbuffer_add(buf, "\r\n", 2);
}

/*
 * Add a "netstring" style string to the buffer, using a cstring as the source.
 *
 * A null string will be transmitted as an empty string.
 */
void
evbuffer_add_netstring_cstring(struct evbuffer *buf, const char *string)
{
	if(! string)
	{
		evbuffer_add_printf(buf, "0:");
	}
	else
	{
		int len = strlen(string);
		evbuffer_add_printf(buf, "%d:", len);
		evbuffer_add_cstring(buf, string);
	}
}

int
evbuffer_add_netstring_vprintf(struct evbuffer *buf, const char *fmt, va_list ap)
{
	struct evbuffer *temp = evbuffer_new();
	int rc = evbuffer_add_vprintf(temp, fmt, ap);
	evbuffer_add_netstring_buffer(buf, temp, true);
	evbuffer_free(temp);
	return rc;
}

int
evbuffer_add_netstring_printf(struct evbuffer *buf, const char *fmt, ...)
{
	int res = -1;
	va_list ap;

	va_start(ap, fmt);
	res = evbuffer_add_netstring_vprintf(buf, fmt, ap);
	va_end(ap);

	return (res);
}

void
evbuffer_add_netstring_buffer(struct evbuffer *buf, struct evbuffer *string, bool drain_src)
{
	evbuffer_add_printf(buf, "%d:", (int)evbuffer_get_length(string));
	if(drain_src)
		evbuffer_remove_buffer(string, buf, evbuffer_get_length(string));
	else
		evbuffer_add_buffer(buf, string);
}

void
evbuffer_add_headers(struct evbuffer *reply_buffer, struct evkeyvalq *headers)
{
	struct evkeyval *header;
	TAILQ_FOREACH(header, headers, next)
	{
		evbuffer_add_cstring(reply_buffer, header->key);
		evbuffer_add(reply_buffer, ": ", 2);
		evbuffer_add_cstring(reply_buffer, header->value);
		evbuffer_add_crlf(reply_buffer);
	}
}

/**
 * Check if the buffer starts with a netstring length and also has all the bytes of the
 * netstring in it.
 *
 * Returns 0 if the complete netstring is available.
 *
 * If the length is available but not the whole body, returns the number of bytes needed
 * to complete the string.
 *
 * If the buffer doesn't have enough data to determine the length, or is otherwise
 * invalid, this returns -1.
 */
static ssize_t
evbuffer_netstring_available(struct evbuffer *input, ssize_t *offset_out, ssize_t *length_out)
{
	char digits_buf[11] = "";
	struct evbuffer_ptr colon_ptr = evbuffer_search(input, ":", 1, NULL);
	ssize_t digits = colon_ptr.pos;
	ssize_t offset = digits + 1;
	ssize_t length;

	/* If the ':' is not found, or at the start of the buffer, no bones */
	if (digits == -1)
	{
		*length_out = 0;
		return -1;
	}

	/* For now treat an empty length as length zero and warn */
	*offset_out = colon_ptr.pos+1;
	if(digits == 0)
	{
		elog(FATAL, "Unexpected empty netstring length.");
		*length_out = 0;
		return 0;
	}

	if(digits >= sizeof(digits_buf))
	{
		elog(FATAL, "Too many digits in netstring length");
		*length_out = 0;
		return 0;
	}

	/* Copy out the digits of the length */
	evbuffer_copyout(input, digits_buf, digits);
	digits_buf[digits] = 0;

	length = *length_out = strtol(digits_buf, NULL, 10);

	if(offset + length > evbuffer_get_length(input))
		return (offset + length - evbuffer_get_length(input));

	return 0;
}

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
evbuffer_remove_netstring_buffer(struct evbuffer *input, struct evbuffer *output)
{
	ssize_t offset=0;
	ssize_t length=0;
	ssize_t rc = evbuffer_netstring_available(input, &offset, &length);
	if(rc == 0)
	{
		evbuffer_drain(input, offset);
		evbuffer_remove_buffer(input, output, length);
	}
	return rc;
}

/*
 * Read a netstring from the input.  The input must contain a complete
 * netstring.  Returns a newly allocated cstring (using palloc), which the caller must
 * free using pfree().  If the input doesn't contain the whole
 * netstring, return NULL.
 */
char *
evbuffer_remove_netstring_cstring(struct evbuffer *input)
{
	ssize_t offset=0;
	ssize_t length=0;
	ssize_t rc = evbuffer_netstring_available(input, &offset, &length);
	if(rc == 0)
	{
		char *result = palloc(length+1);
		evbuffer_drain(input, offset);
		evbuffer_remove(input, result, length);
		result[length] = 0;
		return result;
	}
	else
	{
		return NULL;
	}
}


int
read_netstring_buffer(pgsocket fd, struct evbuffer *input, struct evbuffer *output, int read_size)
{
	for(;;)
	{
		int rc;
		int remaining = evbuffer_remove_netstring_buffer(input, output);
		if(remaining == 0)
			return 0;
		rc = evbuffer_read(input, fd, remaining > 0 ? remaining : read_size);
		if(rc < 0)
			return rc;
		if(rc == 0) /* EOF */
		{
			errno = EPIPE;
			return -1;
		}
	}
	return 0;
}

char *
read_netstring_cstring(pgsocket fd, struct evbuffer *input, int read_size)
{
	char *result=NULL;
	while(evbuffer_get_length(input) == 0 || (result = evbuffer_remove_netstring_cstring(input)) == NULL)
	{
		if(evbuffer_read(input, fd, read_size) <= 0)
			return NULL;
	}
	return result;
}

void
evbuffer_add_json_cstring(struct evbuffer *buf, const char *str)
{
	int len = 1;
	const char *p;

	if (str == NULL)
	{
		evbuffer_add_cstring(buf, "null");
		return;
	}
	for (const char *p = str; *p; p++)
	{
		if (*p < ' ' || strchr("\"\b\f\n\r\t\\", *p) != NULL)
			len++;
		len++;
	}


	/* Reserve space for the new escaped string */
	evbuffer_expand(buf, evbuffer_get_length(buf) + len + 2);

	evbuffer_add_char(buf, '"');
	for (p = str; *p; p++)
	{
		switch (*p)
		{
		case '\b': evbuffer_add_cstring(buf, "\\b"); break;
		case '\f': evbuffer_add_cstring(buf, "\\f"); break;
		case '\n': evbuffer_add_cstring(buf, "\\n"); break;
		case '\r': evbuffer_add_cstring(buf, "\\r"); break;
		case '\t': evbuffer_add_cstring(buf, "\\t"); break;
		case '"': evbuffer_add_cstring(buf, "\\\""); break;
		case '\\': evbuffer_add_cstring(buf, "\\\\"); break;
		default:
			if ((unsigned char) *p < ' ')
				evbuffer_add_printf(buf, "\\u%04x", (int) *p);
			else
				evbuffer_add_char(buf, *p);
			break;
		}
	}
	evbuffer_add_char(buf, '\"');
}

void
evbuffer_add_json_cstring_pair(struct evbuffer *buf, const char *key, const char *value)
{
	evbuffer_add_json_cstring(buf, key);
	evbuffer_add_cstring(buf, ":");
	evbuffer_add_json_cstring(buf, value);
}

const char *cmd_type_strings[] = {
		"GET",
		"POST",
		"HEAD",
		"PUT",
		"DELETE",
		"OPTIONS",
		"TRACE",
		"CONNECT",
		"PATCH",
};
const int num_cmd_type_strings = sizeof(cmd_type_strings) / sizeof(const char *);
const char *
cmd_type_method(enum evhttp_cmd_type cmd_type)
{
	int idx = ffs(cmd_type)-1;
	if(idx >= num_cmd_type_strings || idx == -1)
		return "???";
	return cmd_type_strings[idx];
}

enum evhttp_cmd_type
method_cmd_type(const char *method)
{
	for(int i=0; i < num_cmd_type_strings; i++)
	{
		if(strcmp(cmd_type_strings[i], method) == 0)
			return (1 << i);
	}
	return 1;
}

/* Create a non-blocking socket and bind it */
evutil_socket_t
bound_socket(struct evutil_addrinfo *ai, int reuse)
{
	evutil_socket_t fd;

	int on = 1, r;
	int serrno;

	/* Create listen socket */
	fd = socket_with_flags(ai ? ai->ai_family : AF_INET,
	    SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC, 0);
	if (fd == -1) {
			elog(WARNING, "socket() failed");
			return (-1);
	}

	if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (void *)&on, sizeof(on))<0)
		goto out;
	if (reuse) {
		if (evutil_make_listen_socket_reuseable(fd) < 0)
			goto out;
	}

	if (ai != NULL) {
		r = bind(fd, ai->ai_addr, (ev_socklen_t)ai->ai_addrlen);
		if (r == -1)
			goto out;
	}

	return (fd);

 out:
	serrno = EVUTIL_SOCKET_ERROR();
	evutil_closesocket(fd);
	EVUTIL_SET_SOCKET_ERROR(serrno);
	return (-1);
}


/*
 * Check whether the input starts with the given path component; returns the remainder of the string if so
 * Return NULL if the prefix doesn't match.
 */
const char *
remove_prefix(const char *prefix, const char *input)
{
	int len = strlen(prefix);
	if (strncmp(prefix, input, len) == 0)
		return input + len;
	return NULL;
}

/* NULL safe cstring equality check */
bool
streql(const char *a, const char *b)
{
	if((a == NULL) != (b == NULL))
		return false;
	return strcmp(a, b) == 0;
}

/*
 * Get the uid, gid, and pid of the connected peer.
 */
int
getpeerpideid(int sock, pid_t *pid, uid_t *uid, gid_t *gid)
{
#if defined(SO_PEERCRED)
	/* Linux: use getsockopt(SO_PEERCRED) */
	struct ucred peercred;
	ACCEPT_TYPE_ARG3 so_len = sizeof(peercred);

	if (getsockopt(sock, SOL_SOCKET, SO_PEERCRED, &peercred, &so_len) != 0 ||
		so_len != sizeof(peercred))
		return -1;
	*uid = peercred.uid;
	*gid = peercred.gid;
	*pid = peercred.pid;
	return 0;
#elif defined(LOCAL_PEERCRED)
	/* Debian with FreeBSD kernel: use getsockopt(LOCAL_PEERCRED) */
	struct xucred peercred;
	ACCEPT_TYPE_ARG3 so_len = sizeof(peercred);

	if (getsockopt(sock, 0, LOCAL_PEERCRED, &peercred, &so_len) != 0 ||
		so_len != sizeof(peercred) ||
		peercred.cr_version != XUCRED_VERSION)
		return -1;
	*uid = peercred.cr_uid;
	*gid = peercred.cr_gid;
	*pid = peercred.cr_pid;
	return 0;
#elif defined(HAVE_GETPEERUCRED)
	/* Solaris: use getpeerucred() */
	ucred_t    *ucred;

	ucred = NULL;				/* must be initialized to NULL */
	if (getpeerucred(sock, &ucred) == -1)
		return -1;

	*uid = ucred_geteuid(ucred);
	*gid = ucred_getegid(ucred);
	*pid = ucred_getepid(ucred);
	ucred_free(ucred);

	if (*uid == (uid_t) (-1) || *gid == (gid_t) (-1))
		return -1;
	return 0;
#else
	/* No implementation available on this platform */
	errno = ENOSYS;
	return -1;
#endif
}

void
add_json_content_type_header(struct evkeyvalq *headers)
{
	evhttp_add_header(headers, "Content-Type", "application/json; charset=utf-8");
}


int
evbuffer_parse_scgi_headers(struct evbuffer *input, struct evkeyvalq *headers)
{
	char *key;
	/* elog(LOG, "Headers: %.*s", (int)evbuffer_get_length(input), (char *)evbuffer_pullup(input, -1)); */
	while((key = evbuffer_remove_netstring_cstring(input)) != NULL)
	{
		char *value = evbuffer_remove_netstring_cstring(input);
		if(value == NULL)
			break;
		evhttp_add_header(headers, key, value);
		/* elog(LOG, "Got header; %s: %s", key, value); */
		pfree(value);
	}
	if(evbuffer_get_length(input) != 0)
	{
		return -1;
	}
	return 0;
}

const char *
pstr_uri_append_path_component(const char *base, const char *ext)
{

	char *ext_uri = evhttp_uriencode(ext, strlen(ext), 1);
	const char *result = psprintf("%s/%s", base, ext_uri);
	free(ext_uri);
	return result;
}
