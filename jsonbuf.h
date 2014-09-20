/*
 * jsonbuf.h
 *
 *  Created on: Sep 18, 2014
 *      Author: dobes
 */

#ifndef JSONBUF_H_
#define JSONBUF_H_

struct jsonbuf
{
	char depth;
	struct evbuffer *buf;
	bool empty;
};

/* Prepare jsonbuf struct for use */
void
jsonbuf_init(struct jsonbuf *jp);

/* Reset a jsonbuf back to an empty state */
void
jsonbuf_reset(struct jsonbuf *jp);

/* Start the root object; Call jsonbuf_end_document when done */
void
jsonbuf_start_document(struct jsonbuf *jp);

/* End the root object */
void
jsonbuf_end_document(struct jsonbuf *jp);

/* Add a member to an object with a string for the key and value */
void
jsonbuf_member_cstring(struct jsonbuf *jp, const char *key, const char *value);

/* Add a member to an object with an int value */
void
jsonbuf_member_int(struct jsonbuf *jp, const char *key, int value);

/* Add a member to an object with an bool value */
void
jsonbuf_member_bool(struct jsonbuf *jp, const char *key, bool value);

/* Add a null valued member to an object */
void
jsonbuf_member_null(struct jsonbuf *jp, const char *key);

/* Add a member to an object whose value is an object.  Call jsonbuf_end_object when done adding members */
void
jsonbuf_member_start_object(struct jsonbuf *jp, const char *key);

/* Call to end an object or document */
void
jsonbuf_end_object(struct jsonbuf *jp);

/* Add a member to an object with a string key and start an array value; call jsonbuf_end_array after adding all the elements to the array */
void
jsonbuf_member_start_array(struct jsonbuf *jp, const char *key);

/* Add an array element that is a string */
void
jsonbuf_element_cstring(struct jsonbuf *jp, const char *value);

/*
 * Add a link dict as the value for the key; the value is a dict with the given href, rel, and type
 *
 * If href, rel, and/or type are NULL the attribute will be omitted; generally, however, at least href should
 * be included.
 */
void
jsonbuf_element_link(struct jsonbuf *jp, const char *rel, const char *type, const char *href);

/* Add an array element that is an int */
void
jsonbuf_element_int(struct jsonbuf *jp, int value);

/* Add a boolean value to an array */
void
jsonbuf_element_bool(struct jsonbuf *jp, bool value);

/* Add an array element that is an object */
void
jsonbuf_element_start_object(struct jsonbuf *jp);

/* Add an array element that is an array */
void
jsonbuf_element_start_array(struct jsonbuf *jp);

/* End an array */
void
jsonbuf_end_array(struct jsonbuf *jp);


#endif /* JSONBUF_H_ */
