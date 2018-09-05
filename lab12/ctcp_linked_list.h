/******************************************************************************
 * ctcp_linked_list.h
 * ------------------
 * Linked list functions. Use these to manage a linked list of objects.
 *
 *****************************************************************************/

#ifndef CTCP_LINKED_LIST_H
#define CTCP_LINKED_LIST_H

#include "ctcp_sys.h"

/** Node in the linked list. */
struct ll_node {
  struct ll_node *next;
  struct ll_node *prev;
  void *object;
};
typedef struct ll_node ll_node_t;

/** A linked list. */
struct linked_list {
  ll_node_t *head;
  ll_node_t *tail;
  unsigned int length;
};
typedef struct linked_list linked_list_t;


/**
 * Creates a new linked list and returns it. This must be freed later with
 * ll_destroy().
 *
 * returns: The new linked list.
 */
linked_list_t *ll_create();

/**
 * Destroys a linked list. This will free up its memory and the memory taken
 * by its nodes. This DOES NOT free up the memory taken up by the objects
 * contained within the nodes.
 *
 * list: The list to destroy.
 */
void ll_destroy(linked_list_t *list);

/**
 * Adds an object to the back of the linked list. Returns the linked list node
 * that contains this object. This node must be freed by removing it from the
 * list (via ll_remove()) or destroying the list (ll_destroy()). The contained
 * object MUST be freed by you!
 *
 * list: The list to add to.
 * object: The object to add to the list.
 * returns: The linked list node containing the object. Returns NULL if either
 *          list or object is NULL.
 */
ll_node_t *ll_add(linked_list_t *list, void *object);

/**
 * Adds an object to the front of the linked list. The resulting node is freed
 * by removing it from the list (via ll_remove()) or destroying the
 * corresponding list (ll_destroy()). The containing object MUST be freed by
 * you!
 *
 * list: The list to add to.
 * object: The object to add to the front of the list.
 * returns: The linked list node containing the object. Returns NULL if either
 *          list or object is NULL.
 */
ll_node_t *ll_add_front(linked_list_t *list, void *object);

/**
 * Adds an object to the linked list after the specified node. The resulting
 * node is freed by removing it from the list (via ll_remove()) or destroying
 * the corresponding list (ll_destroy()). The containing object MUST be freed
 * by you!
 *
 * list: The list to add to.
 * node: The node to add after.
 * object: The object to add to the list after the specified node.
 * returns: The linked list node containing the object. Returns NULL if any
 *          parameters are NULL.
 */
ll_node_t *ll_add_after(linked_list_t *list, ll_node_t *node, void *object);

/**
 * Removes a node from the linked list. Frees up the memory taken up by the
 * node, but NOT the memory allocated for the object.
 *
 * list: The list to remove from.
 * node: The node to remove.
 * returns: The object contained within that node, NULL if the list is NULL
 *          or the node is NULL.
 */
void *ll_remove(linked_list_t *list, ll_node_t *node);

/**
 * Searches and returns the node containing the specified object. If it
 * cannot be found or the provided arguments are NULL, returns NULL.
 *
 * list: The list to search in.
 * object: The object to look for.
 * returns: The node if found, NULL otherwise.
 */
ll_node_t *ll_find(linked_list_t *list, void *object);

/**
 * Returns the first element in the list.
 */
ll_node_t *ll_front(linked_list_t *list);

/**
 * Returns the last element in the list.
 */
ll_node_t *ll_back(linked_list_t *list);

/**
 * Returns the length of the list.
 */
unsigned int ll_length(linked_list_t *list);

#endif /* CTCP_LINKED_LIST_H */
