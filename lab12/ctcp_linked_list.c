#include "ctcp_linked_list.h"

linked_list_t *ll_create() {
  linked_list_t *list = calloc(sizeof(linked_list_t), 1);
  list->head = NULL;
  list->tail = NULL;
  list->length = 0;
  return list;
}

void ll_destroy(linked_list_t *list) {
  if (list == NULL)
    return;

  ll_node_t *curr = list->head;
  ll_node_t *next = NULL;
  while (curr != NULL) {
    next = curr->next;
    free(curr);
    curr = next;
  }
  free(list);
}

ll_node_t *ll_create_node(void *object) {
  ll_node_t *node = calloc(sizeof(ll_node_t), 1);
  node->next = NULL;
  node->prev = NULL;
  node->object = object;
  return node;
}

ll_node_t *ll_add(linked_list_t *list, void *object) {
  if (list == NULL || object == NULL)
    return NULL;

  ll_node_t *node = ll_create_node(object);
  /* List is empty. */
  if (list->head == NULL) {
    list->head = node;
    list->tail = node;
  }

  /* List has one or more elements. */
  else {
    list->tail->next = node;
    node->prev = list->tail;
    list->tail = node;
  }

  list->length++;
  return node;
}

ll_node_t *ll_add_front(linked_list_t *list, void *object) {
  if (list == NULL || object == NULL)
    return NULL;

  ll_node_t *node = ll_create_node(object);
  /* List is empty. */
  if (list->head == NULL) {
    list->head = node;
    list->tail = node;
  }

  /* List has one or more elements. */
  else {
    node->next = list->head;
    list->head->prev = node;
    list->head = node;
  }

  list->length++;
  return node;
}

ll_node_t *ll_add_after(linked_list_t *list, ll_node_t *node, void *object) {
  if (list == NULL || node == NULL || object == NULL)
    return NULL;

  ll_node_t *new_node = ll_create_node(object);
  /* Update pointers. */
  new_node->prev = node;
  new_node->next = node->next;
  if (node->next != NULL)
    node->next->prev = new_node;
  node->next = new_node;

  /* Added to end of list. */
  if (node == list->tail)
    list->tail = new_node;

  list->length++;
  return new_node;
}

void *ll_remove(linked_list_t *list, ll_node_t *node) {
  if (list == NULL || node == NULL)
    return NULL;
  void *object = node->object;

  /* Update linked list pointers. */
  if (node == list->head)
    list->head = node->next;
  else
    node->prev->next = node->next;

  if (node == list->tail)
    list->tail = node->prev;
  else
    node->next->prev = node->prev;

  /* Free memory. */
  free(node);
  list->length--;

  return object;
}

ll_node_t *ll_find(linked_list_t *list, void *object) {
  if (list == NULL || object == NULL)
    return NULL;

  ll_node_t *curr = list->head;
  while (curr != NULL) {
    if (curr->object == object) {
      return curr;
    }
    curr = curr->next;
  }
  return NULL;
}

ll_node_t *ll_front(linked_list_t *list) {
  return list->head;
}

ll_node_t *ll_back(linked_list_t *list) {
  return list->tail;
}

unsigned int ll_length(linked_list_t *list) {
  return list->length;
}
