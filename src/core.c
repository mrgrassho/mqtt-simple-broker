#include <string.h>
#include <stdlib.h>
#include "core.h"

static int compare_cid(void *c1, void *c2) {
    return strcmp(((struct subscriber *) c1)->client->client_id,
                  ((struct subscriber *) c2)->client->client_id);
}

struct topic *topic_create(const char *name) {
    struct topic *t = malloc(sizeof(*t));
    topic_init(t, name);
    return t;
}

void topic_init(struct topic *t, const char *name) {
    t->name = name;
    t->subscribers = list_create(NULL);
}

void topic_add_subscriber(struct topic *t,
                          struct sol_client *client,
                          unsigned qos,
                          bool cleansession) {
    struct subscriber *sub = malloc(sizeof(*sub));
    sub->client = client;
    sub->qos = qos;
    t->subscribers = list_push(t->subscribers, sub);

    // It must be added to the session if cleansession is false
    if (!cleansession)
        client->session.subscriptions =
            list_push(client->session.subscriptions, t);

}

void topic_del_subscriber(struct topic *t,
                          struct sol_client *client,
                          bool cleansession) {
    list_remove_node(t->subscribers, client, compare_cid);

    // TODO remomve in case of cleansession == false
}

void sol_topic_put(struct sol *sol, struct topic *t) {
    trie_insert(&sol->topics, t->name, t);
}

void sol_topic_del(struct sol *sol, const char *name) {
    trie_delete(&sol->topics, name);
}

struct topic *sol_topic_get(struct sol *sol, const char *name) {
    struct topic *ret_topic;
    trie_find(&sol->topics, name, (void *) &ret_topic);
    return ret_topic;
}