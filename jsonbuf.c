
#include <c.h>
#include <port.h>
#include <stdlib.h>
#include "jsonbuf.h"
#include "util.h"
#include "event2/buffer.h"

static void
jsonbuf_start_composite(struct jsonbuf *jp, char opener);

static void
jsonbuf_end_composite(struct jsonbuf *jp, char closer);

static void
jsonbuf_indent(struct jsonbuf *jp);

static void
jsonbuf_newline_indent(struct jsonbuf *jp);

static void
jsonbuf_member_start(struct jsonbuf *jp, const char *key);

void
jsonbuf_init(struct jsonbuf *jp)
{
	jp->depth = -1;
	jp->buf = evbuffer_new();
	jp->empty = true;
}

void
jsonbuf_reset(struct jsonbuf *jp)
{
	jp->depth = -1;
	evbuffer_drain(jp->buf, SIZE_MAX);
	jp->empty = true;
}

const char spaces[] = "                "; /* 16 spaces */
static void evbuffer_add_spaces(struct evbuffer *buf, int count)
{
	while(count > 0)
	{
		evbuffer_add(buf, spaces, count >= 16 ? 16 : count);
		count -= 16;
	}
}

static void
jsonbuf_indent(struct jsonbuf *jp)
{
	evbuffer_add_spaces(jp->buf, jp->depth);
}

static void
jsonbuf_newline_indent(struct jsonbuf *jp)
{
	evbuffer_add_crlf(jp->buf);
	jsonbuf_indent(jp);
}


static void
jsonbuf_start_composite(struct jsonbuf *jp, char opener)
{
	evbuffer_add_char(jp->buf, opener);
	jp->depth++;
	jp->empty = true;
}

static void
jsonbuf_end_composite(struct jsonbuf *jp, char closer)
{
	jp->depth--;
	if(jp->empty)
		jp->empty = false;
	else
		jsonbuf_newline_indent(jp);
	evbuffer_add_char(jp->buf, closer);
}

void
jsonbuf_start_document(struct jsonbuf *jp)
{
	jsonbuf_start_composite(jp, '{');
}

void
jsonbuf_end_document(struct jsonbuf *jp)
{
	jsonbuf_end_composite(jp, '}');
	evbuffer_add_crlf(jp->buf);
}

static void
jsonbuf_member_start(struct jsonbuf *jp, const char *key)
{
	if(jp->empty)
		jp->empty = false;
	else
		evbuffer_add_char(jp->buf, ',');

	jsonbuf_newline_indent(jp);
	evbuffer_add_json_cstring(jp->buf, key);
	evbuffer_add_cstring(jp->buf, " : ");

}

void
jsonbuf_member_cstring(struct jsonbuf *jp, const char *key, const char *value)
{
	jsonbuf_member_start(jp, key);
	evbuffer_add_json_cstring(jp->buf, value);
}

void
jsonbuf_member_int(struct jsonbuf *jp, const char *key, int value)
{
	char buf[32];
	sprintf(buf, "%d", value);
	jsonbuf_member_start(jp, key);
	evbuffer_add_cstring(jp->buf, buf);
}

void
jsonbuf_member_null(struct jsonbuf *jp, const char *key)
{
	jsonbuf_member_start(jp, key);
	evbuffer_add_cstring(jp->buf, "null");
}

void
jsonbuf_member_bool(struct jsonbuf *jp, const char *key, bool value)
{
	jsonbuf_member_start(jp, key);
	evbuffer_add_cstring(jp->buf, value?"true":"false");
}

void
jsonbuf_member_start_object(struct jsonbuf *jp, const char *key)
{
	jsonbuf_member_start(jp, key);
	jsonbuf_start_composite(jp, '{');
}

void
jsonbuf_end_object(struct jsonbuf *jp)
{
	jsonbuf_end_composite(jp, '}');
}

void
jsonbuf_member_start_array(struct jsonbuf *jp, const char *key)
{
	jsonbuf_member_start(jp, key);
	jsonbuf_start_composite(jp, '[');
}

void
jsonbuf_end_array(struct jsonbuf *jp)
{
	jsonbuf_end_composite(jp, ']');
}

static void
jsonbuf_element_start(struct jsonbuf *jp)
{
	if(jp->empty)
		jp->empty = false;
	else
		evbuffer_add_char(jp->buf, ',');

	jsonbuf_newline_indent(jp);
}

void
jsonbuf_element_cstring(struct jsonbuf *jp, const char *value)
{
	jsonbuf_element_start(jp);
	evbuffer_add_json_cstring(jp->buf, value);
}

void
jsonbuf_element_link(struct jsonbuf *jp, const char *rel, const char *type, const char *href)
{
	jsonbuf_element_start_object(jp);
	if(rel) jsonbuf_member_cstring(jp, "rel", rel);
	if(type) jsonbuf_member_cstring(jp, "type", type);
	if(href) jsonbuf_member_cstring(jp, "href", href);
	jsonbuf_end_object(jp);
}

void
jsonbuf_element_int(struct jsonbuf *jp, int value)
{
	jsonbuf_element_start(jp);
	evbuffer_add_printf(jp->buf, "%d", value);

}

void
jsonbuf_element_bool(struct jsonbuf *jp, bool value)
{
	jsonbuf_element_start(jp);
	evbuffer_add_printf(jp->buf, value ? "true" : "false");
}

void
jsonbuf_element_start_object(struct jsonbuf *jp)
{
	jsonbuf_element_start(jp);
	jsonbuf_start_composite(jp, '{');
}

void
jsonbuf_element_start_array(struct jsonbuf *jp)
{
	jsonbuf_element_start(jp);
	jsonbuf_start_composite(jp, '[');
}
