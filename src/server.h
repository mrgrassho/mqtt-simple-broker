#ifndef SERVER_H
#define SERVER_H

/*
 * Epoll default settings for concurrent events monitored and timeout, -1
 * means no timeout at all, blocking undefinitely
 */
#define EPOLL_MAX_EVENTS    256
#define EPOLL_TIMEOUT       -1

/* Error codes for packet reception, signaling respectively
 * - client disconnection
 * - error reading packet
 * - error packet sent exceeds size defined by configuration (generally default
 *   to 2MB)
 */
#define ERRCLIENTDC         1
#define ERRPACKETERR        2
#define ERRMAXREQSIZE       3

/* Return code of handler functions, signaling if there's payload data to be
 * sent out or if the server just need to re-arm closure for reading incoming
 * bytes
 */
#define REARM_R             0
#define REARM_W             1

int start_server(const char *, const char *);

/* Global informations statistics structure */
struct sol_info {
    /* Number of clients currently connected */
    int nclients;
    /* Total number of clients connected since the start */
    int nconnections;
    /* Timestamp of the start time */
    long long start_time;
    /* Total number of bytes received */
    long long bytes_recv;
    /* Total number of bytes sent out */
    long long bytes_sent;
    /* Total number of sent messages */
    long long messages_sent;
    /* Total number of received messages */
    long long messages_recv;
};

/* Add periodic task for publishing stats on SYS topics */
// TODO Implement
struct closure sys_closure = {
    .fd = 0,
    .payload = NULL,
    .args = &sys_closure,
    .call = publish_stats
};

generate_uuid(sys_closure.closure_id);

/* Schedule as periodic task to be executed every N seconds */
evloop_add_periodic_task(event_loop, conf->stats_pub_interval,
                         0, &sys_closure);

#endif