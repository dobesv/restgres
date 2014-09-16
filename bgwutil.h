/*
 * bgwutil.h
 *
 *  Created on: Sep 14, 2014
 *      Author: dobes
 */

#ifndef BGWUTIL_H_
#define BGWUTIL_H_

void watch_for_signals_and_postmaster_death(struct event_base *base);

struct evutil_addrinfo *get_domain_socket_addr();

#endif /* BGWUTIL_H_ */
