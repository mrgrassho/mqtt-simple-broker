#ifndef NETWORK_H
#define NETWORK_H

#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>
#include "util.h"

// Socket families
#define UNIX    0
#define INET    1

/* Set non-blocking socket */
int set_nonblocking(int);

/*
 * Set TCP_NODELAY flag to true, disabling Nagle's algorithm, no more waiting
 * for incoming packets on the buffer
 */
int set_tcp_nodelay(int);

/* Auxiliary function for creating epoll server */
int create_and_bind(const char *, const char *, int);

/*
 * Create a non-blocking socket and make it listen on the specfied address and
 * port
 */
int make_listen(const char *, const char *, int);

/* Accept a connection and add it to the right epollfd */
int accept_connection(int);

/* I/O management functions */

/*
 * Send all data in a loop, avoiding interruption based on the kernel buffer
 * availability
 */
ssize_t send_bytes(int, const unsigned char *, size_t);

/*
 * Receive (read) an arbitrary number of bytes from a file descriptor and
 * store them in a buffer
 */
ssize_t recv_bytes(int, unsigned char *, size_t);

typedef union epoll_data {
   void        *ptr;
   int          fd;
   uint32_t     u32;
   uint64_t     u64;
} epoll_data_t;

/* Event loop wrapper structure, define an EPOLL loop and his status. The
 * EPOLL instance use EPOLLONESHOT for each event and must be re-armed
 * manually, in order to allow future uses on a multithreaded architecture.
 */
struct evloop {
    int epollfd;
    int max_events;
    int timeout;
    int status;
    struct epoll_event *events;
    /* Dynamic array of periodic tasks, a pair descriptor - closure */
    int periodic_maxsize;
    int periodic_nr;
    struct {
        int timerfd;
        struct closure *closure;
    } **periodic_tasks;
} evloop;

typedef void callback(struct evloop *, void *);

/*
 * Callback object, represents a callback function with an associated
 * descriptor if needed, args is a void pointer which can be a structure
 * pointing to callback parameters and closure_id is a UUID for the closure
 * itself.
 * The last two fields are payload, a serialized version of the result of
 * a callback, ready to be sent through wire and a function pointer to the
 * callback function to execute.
 */
struct closure {
    int fd;
    void *obj;
    void *args;
    char closure_id[UUID_LEN];
    struct bytestring *payload;
    callback *call;
};

struct evloop *evloop_create(int, int);
void evloop_init(struct evloop *, int, int);
void evloop_free(struct evloop *);

/*
 * Blocks in a while(1) loop awaiting for events to be raised on monitored
 * file descriptors and executing the paired callback previously registered
 */
int evloop_wait(struct evloop *);

/*
 * Register a closure with a function to be executed every time the
 * paired descriptor is re-armed.
 */
void evloop_add_callback(struct evloop *, struct closure *);

/*
 * Register a periodic closure with a function to be executed every
 * defined interval of time.
 */
void evloop_add_periodic_task(struct evloop *,
                              int,
                              unsigned long long,
                              struct closure *);

/*
 * Unregister a closure by removing the associated descriptor from the
 * EPOLL loop
 */
int evloop_del_callback(struct evloop *, struct closure *);

/*
 * Rearm the file descriptor associated with a closure for read action,
 * making the event loop to monitor the callback for reading events
 */
int evloop_rearm_callback_read(struct evloop *, struct closure *);

/*
 * Rearm the file descriptor associated with a closure for write action,
 * making the event loop to monitor the callback for writing events
 */
int evloop_rearm_callback_write(struct evloop *, struct closure *);

/* Epoll management functions */
int epoll_add(int, int, int, void *);

/*
 * Modify an epoll-monitored descriptor, automatically set EPOLLONESHOT in
 * addition to the other flags, which can be EPOLLIN for read and EPOLLOUT for
 * write
 */
int epoll_mod(int, int, int, void *);

/*
 * Remove a descriptor from an epoll descriptor, making it no-longer monitored
 * for events
 */
int epoll_del(int, int);

#endif