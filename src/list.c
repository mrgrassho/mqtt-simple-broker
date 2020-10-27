#include "list.h"
#include <stdlib.h>

static struct list_node *list_node_remove(struct list_node *,
                                          struct list_node *,
                                          compare_func, int *);

/*
 * Create a list, initializing all fields
 */
List *list_create(int (*destructor)(struct list_node *)) {
    List *l = malloc(sizeof(List));
    if (!l)
        return NULL;

    // set default values to the List structure fields
    l->head = l->tail = NULL;
    l->len = 0L;
    // TODO if NULL set default destructor
    l->destructor = destructor;

    return l;
}

/*
 * Destroy a list, releasing all allocated memory
 */
void list_release(List *l, int deep) {
    if (!l)
        return;
    struct list_node *h = l->head;
    struct list_node *tmp;

    // free all nodes
    while (l->len--) {
        tmp = h->next;
        if (l->destructor)
            l->destructor(h);
        else {
            if (h) {
                if (h->data && deep == 1)
                    free(h->data);
                free(h);
            }
        }
        h = tmp;
    }

    // free List structure pointer
    free(l);
}

unsigned long list_size(const List *list) {
    return list->len;
}

/*
 * Destroy a list, releasing all allocated memory but the list itself
 */
void list_clear(List *l, int deep) {
    if (!l || !l->head)
        return;
    struct list_node *h = l->head;
    struct list_node *tmp;

    // free all nodes
    while (l->len--) {
        tmp = h->next;
        if (h) {
            if (h->data && deep == 1)
                free(h->data);
            free(h);
        }
        h = tmp;
    }
    l->head = l->tail = NULL;
    l->len = 0L;
}

/*
 * Insert value at the front of the list
 * Complexity: O(1)
 */
List *list_push(List *l, void *val) {
    struct list_node *new_node = malloc(sizeof(struct list_node));
    if (!new_node)
        return NULL;
    new_node->data = val;
    if (l->len == 0) {
        l->head = l->tail = new_node;
        new_node->next = NULL;
    } else {
        new_node->next = l->head;
        l->head = new_node;
    }
    l->len++;
    return l;
}

/*
 * Insert value at the back of the list
 * Complexity: O(1)
 */
List *list_push_back(List *l, void *val) {
    struct list_node *new_node = malloc(sizeof(struct list_node));
    if (!new_node)
        return NULL;
    new_node->data = val;
    new_node->next = NULL;
    if (l->len == 0) {
        l->head = l->tail = new_node;
    } else {
        l->tail->next = new_node;
        l->tail = new_node;
    }
    l->len++;
    return l;
}

void list_remove(List *l, struct list_node *node, compare_func cmp) {
    if (!l || !node)
        return;
    int counter = 0;
    l->head = list_node_remove(l->head, node, cmp, &counter);
    l->len -= counter;
}

static struct list_node *list_node_remove(struct list_node *head,
                                          struct list_node *node,
                                          compare_func cmp, int *counter) {
    if (!head)
        return NULL;
    if (cmp(head, node) == 0) {
        struct list_node *tmp_next = head->next;
        free(head);
        head = NULL;

        // Update remove counter
        (*counter)++;
        return tmp_next;
    }
    head->next = list_node_remove(head->next, node, cmp, counter);
    return head;
}

static struct list_node *list_remove_single_node(struct list_node *head,
                                                 void *data,
                                                 struct list_node **ret,
                                                 compare_func cmp) {
    if (!head)
        return NULL;

    // We want the first match
    if (cmp(head, data) == 0 && !*ret) {
        struct list_node *tmp_next = head->next;
        *ret = head;
        return tmp_next;
    }
    head->next = list_remove_single_node(head->next, data, ret, cmp);
    return head;
}

struct list_node *list_remove_node(List *list, void *data, compare_func cmp) {
    if (list->len == 0 || !list)
        return NULL;
    struct list_node *node = NULL;
    list_remove_single_node(list->head, data, &node, cmp);
    if (node) {
        list->len--;
        node->next = NULL;
    }
    return node;
}

/* Insert a new list node in a list maintaining the order of the list */
struct list_node *list_sort_insert(struct list_node **head,
                                   struct list_node *new, cmp cmp_func) {
    if (!*head || cmp_func(*head, new) >= 0) {
        new->next = *head;
        *head = new;
    } else {
        struct list_node *cur;
        cur = *head;
        while (cur->next && cmp_func(cur->next, new) < 0)
            cur = cur->next;
        new->next = cur->next;
        cur->next = new;
    }
    return *head;
}

/*
 * Returns a pointer to a node near the middle of the list,
 * after having truncated the original list before that point.
 */
struct list_node *bisect_list(struct list_node *head) {
    /* The fast pointer moves twice as fast as the slow pointer. */
    /* The prev pointer points to the node preceding the slow pointer. */
    struct list_node *fast = head, *slow = head, *prev = NULL;
    while (fast != NULL && fast->next != NULL) {
        fast = fast->next->next;
        prev = slow;
        slow = slow->next;
    }
    if (prev != NULL)
        prev->next = NULL;
    return slow;
}