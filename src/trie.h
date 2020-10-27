#ifndef TRIE_H
#define TRIE_H

#include <stdio.h>
#include <stdbool.h>
#include "list.h"

typedef struct trie Trie;

/*
 * Trie node, it contains a fixed size array (every node can have at max the
 * alphabet length size of children), a flag defining if the node represent
 * the end of a word and then if it contains a value defined by data.
 */
struct trie_node {
    char chr;
    List *children;
    void *data;
};

/*
 * Trie ADT, it is formed by a root struct trie_node, and the total size of the
 * Trie
 */
struct trie {
    struct trie_node *root;
    size_t size;
};

// Returns new trie node (initialized to NULLs)
struct trie_node *trie_create_node(char);

// Returns a new Trie, which is formed by a root node and a size
struct trie *trie_create(void);

void trie_init(Trie *);

// Return the size of the trie
size_t trie_size(const Trie *);

/*
 * The leaf represents the node with the associated data
 *           .
 *          / \
 *         h   s: s -> value
 *        / \
 *       e   k: hk -> value
 *      /
 *     l: hel -> value
 *
 * Here we got 3 <key:value> pairs:
 * - s   -> value
 * - hk  -> value
 * - hel -> value
 */
void *trie_insert(Trie *, const char *, const void *);

bool trie_delete(Trie *, const char *);

/* Returns true if key presents in trie, else false, the last pointer to
   pointer is used to store the value associated with the searched key, if
   present */
bool trie_find(const Trie *, const char *, void **);

void trie_node_free(struct trie_node *, size_t *);

void trie_release(Trie *);

/* Remove all keys matching a given prefix in a linear time complexity (O(n))*/
void trie_prefix_delete(Trie *, const char *);

/*
 * Apply a given function to all ndoes which keys match a given prefix. The
 * function accepts two arguments, a struct trie_node pointer which correspond
 * to each node on the trie after the prefix node and a void pointer, used for
 * additional data which can be useful to the execution of `mapfunc`.
 */
void trie_prefix_map_tuple(Trie *, const char *,
                           void (*mapfunc)(struct trie_node *, void *), void *);

#endif