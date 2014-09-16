#ifndef SENDRECV_FD_H_
#define SENDRECV_FD_H_

#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>
#include <errno.h>


int
recvfd(int s);

int
sendfd(int s, int fd);

#endif
