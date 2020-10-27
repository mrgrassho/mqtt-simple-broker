#ifndef CONFIG_H
#define CONFIG_H

#include <stdio.h>

// Default parameters

#define VERSION                     "0.0.1"
#define DEFAULT_SOCKET_FAMILY       INET
#define DEFAULT_LOG_LEVEL           DEBUG
#define DEFAULT_LOG_PATH            "/tmp/sol.log"
#define DEFAULT_CONF_PATH           "/etc/sol/sol.conf"
#define DEFAULT_HOSTNAME            "127.0.0.1"
#define DEFAULT_PORT                "1883"
#define DEFAULT_MAX_MEMORY          "2GB"
#define DEFAULT_MAX_REQUEST_SIZE    "2MB"
#define DEFAULT_STATS_INTERVAL      "10s"

struct config {
    /* Sol version <MAJOR.MINOR.PATCH> */
    const char *version;
    /* Eventfd to break the epoll_wait loop in case of signals */
    int run;
    /* Logging level, to be set by reading configuration */
    int loglevel;
    /* Epoll wait timeout, define even the number of times per second that the
       system will check for expired keys */
    int epoll_timeout;
    /* Socket family (Unix domain or TCP) */
    int socket_family;
    /* Log file path */
    char logpath[0xFF];
    /* Hostname to listen on */
    char hostname[0xFF];
    /* Port to open while listening, only if socket_family is INET,
     * otherwise it's ignored */
    char port[0xFF];
    /* Max memory to be used, after which the system starts to reclaim back by
     * freeing older items stored */
    size_t max_memory;
    /* Max memory request can allocate */
    size_t max_request_size;
    /* TCP backlog size */
    int tcp_backlog;
    /* Delay between every automatic publish of broker stats on topic */
    size_t stats_pub_interval;
};

extern struct config *conf;

void config_set_default(void);
void config_print(void);
int config_load(const char *);

char *time_to_string(size_t);
char *memory_to_string(size_t);

#endif