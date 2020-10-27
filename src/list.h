#ifndef LIST_H
#define LIST_H

struct list_node {
    void *data;
    struct list_node *next;
};

typedef struct list {
    struct list_node *head;
    struct list_node *tail;
    unsigned long len;
    int (*destructor)(struct list_node *);
} List;

/*
 * Compare function, accept two void * arguments, generally referring a node
 * and his subsequent
 */
typedef int (*compare_func)(void *, void *);

/* Create an empty list */
List *list_create(int (*destructor)(struct list_node*));

/*
 * Release a list, accept a integer flag to control the depth of the free call
 * (e.g. going to free also data field of every node)
 */
void list_release(List *, int);

/* Return list size */
unsigned long list_size(const List *);

/* Clear out the list without de-allocating it */
void list_clear(List *, int);

/* Insert data into a node and push it to the front of the list */
List *list_push(List *, void *);

/* Insert data into a node and push it to the back of the list */
List *list_push_back(List *, void *);

/*
 * Remove a node from the list based on a compare function that must be
 * previously defined and passed in as a function pointer, accept two void
 * *args, which generally means a node and his subsequent
 */
void list_remove(List *, struct list_node *, compare_func);

/*
 * Remove a single node from the list, the first one satisfy compare_func
 * criteria, without de-allocating it
 */
struct list_node *list_remove_node(List *, void *, compare_func);

/* Comapare function for merge_sort application */
typedef int cmp(void *, void *);

/* Insert a new node into a list while maintaining the order of the elements */
struct list_node *list_sort_insert(struct list_node **,
                                   struct list_node *, compare_func);

/* Divide a list in 2 sublists at roughly the middle of the original list */
struct list_node *bisect_list(struct list_node *);

#endif