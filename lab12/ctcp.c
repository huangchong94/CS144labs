/******************************************************************************
 * ctcp.c
 * ------
 * Implementation of cTCP done here. This is the only file you need to change.
 * Look at the following files for references and useful functions:
 *   - ctcp.h: Headers for this file.
 *   - ctcp_iinked_list.h: Linked list functions for managing a linked list.
 *   - ctcp_sys.h: Connection-related structs and functions, cTCP segment
 *                 definition.
 *   - ctcp_utils.h: Checksum computation, getting the current time.
 *
 *****************************************************************************/

#include "ctcp.h"
#include "ctcp_linked_list.h"
#include "ctcp_sys.h"
#include "ctcp_utils.h"

/**
 * Connection state.
 *
 * Stores per-connection information such as the current sequence number,
 * unacknowledged packets, etc.
 *
 * You should add to this to store other fields you might need.
 */
struct ctcp_state {
  struct ctcp_state *next;  /* Next in linked list */
  struct ctcp_state **prev; /* Prev in linked list */

  conn_t *conn;             /* Connection object -- needed in order to figure
                               out destination when sending */
  linked_list_t *segments;  /* Linked list of segments sent to this connection.
                               It may be useful to have multiple linked lists
                               for unacknowledged segments, segments that
                               haven't been sent, etc. Lab 1 uses the
                               stop-and-wait protocol and therefore does not
                               necessarily need a linked list. You may remove
                               this if this is the case for you */


  int recv_ack; //仅用于停等式
  linked_list_t *unacked_segments;
  uint16_t send_window;
  uint16_t recv_window;
  uint32_t seqno;
  uint32_t nextseqno;
  uint32_t ackno;  
  uint32_t send_base;  
  int sent_fin;
  int recv_fin;
  int rt_timeout;
};

struct ctcp_send_record {
  ctcp_segment_t *segment;
  long send_time;
  int rt_count;
};

typedef struct ctcp_send_record ctcp_send_record_t;

int CTCP_HDR_SIZE = sizeof(ctcp_segment_t);
/**
 * Linked list of connection states. Go through this in ctcp_timer() to
 * resubmit segments and tear down connections.
 */
static ctcp_state_t *state_list;

/* FIXME: Feel free to add as many helper functions as needed. Don't repeat
          code! Helper functions make the code clearer and cleaner. */

ctcp_segment_t *ctcp_create_segment(ctcp_state_t *state, char *data, uint16_t data_len, uint32_t flags) {
  uint16_t segment_len = data_len + CTCP_HDR_SIZE;
  ctcp_segment_t *segment = (ctcp_segment_t*)calloc(segment_len, 1);
  if (data_len > 0)
    memcpy(segment->data, data, data_len);
  segment->seqno = htonl(state->nextseqno);
  segment->ackno = htonl(state->ackno); 
  segment->flags = flags;   
  segment->window = htons(state->recv_window);
  segment->len = htons(segment_len); 
  segment->cksum = cksum(segment, segment_len);
  return segment;
}

int ctcp_send_segment(ctcp_state_t *state, ctcp_segment_t *segment) {
  int segment_len = ntohs(segment->len);
  int byte_sent = conn_send(state->conn, segment, segment_len);
  return byte_sent;
}

void update_state_after_sending_data(ctcp_state_t *state, int data_len, int is_fin) {
  state->seqno = state->nextseqno;
  if (data_len > 0) 
    state->nextseqno += data_len;
  else if (data_len==0 && is_fin) {
    state->nextseqno += 1;
    state->sent_fin = 1;
  }
//  printf("[INFO] data_len %d nextseqno %d\n", data_len, state->nextseqno);
}

int is_corrupt(ctcp_segment_t *segment) {
  uint16_t segment_cksum = segment->cksum;
  segment->cksum = 0;
  int result = cksum(segment, ntohs(segment->len)) != segment_cksum;
  segment->cksum = segment_cksum;
  return result; 
}

int ctcp_send_ack(ctcp_state_t *state) {
  ctcp_segment_t *segment = ctcp_create_segment(state, NULL, 0, TH_ACK);
  int byte_sent = ctcp_send_segment(state, segment);
  free(segment);
  if (byte_sent > 0)
    return 0;
  return -1;
}

void save_segment_to_linked_list(ctcp_segment_t *segment, linked_list_t *list) {
  if (list->length == 0)
    ll_add(list, segment);
  else {
    ctcp_segment_t *head_segment = (ctcp_segment_t*)(ll_front(list)->object);
    int head_seqno = ntohl(head_segment->seqno);
    int segment_seqno = ntohl(segment->seqno);
    if (segment_seqno < head_seqno)
      ll_add_front(list, segment); 
    else if (segment_seqno > head_seqno){
      ll_node_t *traverse = ll_front(list);      
      while (traverse->next) {
        int traverse_next_seqno = ntohl(((ctcp_segment_t*)traverse->next->object)->seqno);
	if (traverse_next_seqno > segment_seqno)
	  break;
        traverse = traverse->next;
      }
      ll_add_after(list, traverse, segment);
    }
  }

}

int get_msec() {
  struct timeval timeval;
  gettimeofday(&timeval, NULL);
  //printf("[INFO] tv_sec = %ld\n", timeval.tv_sec);
  return (timeval.tv_sec-1515661000)*1000 + timeval.tv_usec / 1000;  
}

ctcp_send_record_t *ctcp_create_send_record(ctcp_segment_t *segment, int send_time) {
  ctcp_send_record_t *record = (ctcp_send_record_t*)malloc(sizeof(ctcp_send_record_t));
  record->segment = segment;
  record->send_time = send_time;
  record->rt_count = 0;
  return record;
}

void update_unacked_segments(ctcp_state_t *state, int segment_ackno) {
  if (state->unacked_segments->length == 0)
    return;
  
  ll_node_t *traverse = ll_front(state->unacked_segments);
  while (traverse) {
    ctcp_send_record_t *record = (ctcp_send_record_t*)(traverse->object);
    ctcp_segment_t *segment = record->segment;
    int traverse_seqno = ntohl(segment->seqno);
    int data_len = ntohs(segment->len) - CTCP_HDR_SIZE;
    if (segment->flags & TH_FIN)
      data_len = 1;
    if (traverse_seqno + data_len <= segment_ackno) {
      ll_node_t *traverse_next = traverse->next;
      ll_remove(state->unacked_segments, traverse);
      traverse = traverse_next;
      free(record);
      free(segment); 
    }
    else
      break;
  }
}

ctcp_state_t *ctcp_init(conn_t *conn, ctcp_config_t *cfg) {
  /* Connection could not be established. */
  if (conn == NULL) {
    return NULL;
  }

  /* Established a connection. Create a new state and update the linked list
     of connection states. */
  ctcp_state_t *state = calloc(sizeof(ctcp_state_t), 1);
  
  state->recv_ack = true;
  state->segments = ll_create();
  state->unacked_segments = ll_create();
  state->send_window = cfg->send_window;
  state->recv_window = cfg->recv_window;
  state->seqno = 1;
  state->nextseqno = 1;
  state->ackno = 1;
  state->send_base = 1;
  state->sent_fin = 0;
  state->recv_fin = 0;
  state->rt_timeout = cfg->rt_timeout;

  state->next = state_list;
  state->prev = &state_list;
  if (state_list)
    state_list->prev = &state->next;
  state_list = state;

  /* Set fields. */
  state->conn = conn;

  free(cfg);
  return state;
}

void ctcp_destroy(ctcp_state_t *state) {
  /* Update linked list. */
  if (state->next)
    state->next->prev = state->prev;

  *state->prev = state->next;
  conn_remove(state->conn);

  /* TODO 应该写一个接收函数指针的泛型ll_destroy 但是函数指针用法记不清了*/
  ll_node_t *traverse = ll_front(state->segments);
  ll_node_t *next;
  while (traverse) {
    free(traverse->object);
    next = traverse->next;
    free(traverse);
    traverse = next; 
  }
  free(state->segments);

  traverse = ll_front(state->unacked_segments);
  while (traverse) {
    ctcp_send_record_t *record = (ctcp_send_record_t*)(traverse->object);
    free(record->segment);
    free(record);
    next = traverse->next;
    free(traverse);
    traverse = next;
  }
  free(state->unacked_segments);

  free(state);
  end_client();
}

void ctcp_read(ctcp_state_t *state) {
  if (state->sent_fin)
    return;
  uint32_t max_size = state->send_base + state->send_window - state->nextseqno;
  if (max_size > MAX_SEG_DATA_SIZE)
    max_size = MAX_SEG_DATA_SIZE;
//  printf("[INFO] max_size %d\n", max_size);
  if (state->send_window == MAX_SEG_DATA_SIZE && !state->recv_ack)
    max_size = 0;
  if (max_size == 0)
    return;
  char *buf = (char*)malloc(max_size);
  int data_len = conn_input(state->conn, buf, max_size);
  uint32_t flags = 0;
  if (data_len <= 0) {
    data_len = 0;
    flags = TH_ACK | TH_FIN;
    fprintf(stderr, "EOF\n");
  }
  else {
    flags = TH_ACK;
  }
  ctcp_segment_t* segment = ctcp_create_segment(state, buf, data_len, flags);
  //printf("[INFO] ctcp read before free\n");
  free(buf);
 // printf("[INFO] ctcp read after free\n");
   ctcp_send_segment(state, segment);
  int send_time = get_msec();
  update_state_after_sending_data(state, data_len, flags&TH_FIN);
  ctcp_send_record_t *record = ctcp_create_send_record(segment, send_time);
  ll_add(state->unacked_segments, record);
  state->recv_ack = false; //对于滑窗无意义
}

void ctcp_receive(ctcp_state_t *state, ctcp_segment_t *segment, size_t len) {
  //printf("[INFO] receive segment\n");
  if (is_corrupt(segment)) {
    free(segment);
    return;
  }

  uint32_t segment_seqno = ntohl(segment->seqno);
  uint32_t segment_ackno = ntohl(segment->ackno);

  /* 注意如果要实现快重传，那么当segment_seqno > state->ackno时需要send duplicate ack */
  /* 但是这里不打算实现快重传，所以就不管了 */
  if (segment_seqno < state->ackno) {
    if (state->unacked_segments->length == 0)
    /* 这里说明丢ack了 如果丢失的ack segment本身带有数据无需再次发送ack，
       ctcp_timer会自动重传该segment，但是如果是不带数据的ack segment则必须
       重发ack */
      ctcp_send_ack(state);
      free(segment);
      return;
  }
  if (segment_seqno == state->ackno) {
    state->recv_ack = true;
    if (segment_ackno > state->send_base)
      state->send_base = segment_ackno;
    state->send_window = ntohs(segment->window);
  }
  uint16_t segment_len = ntohs(segment->len);
  uint16_t payload_size = segment_len - CTCP_HDR_SIZE;
  int is_data_segment = payload_size > 0;
  if (is_data_segment) {
   // printf("[INFO] is_data_segment\n");
    save_segment_to_linked_list(segment, state->segments);
    ctcp_output(state);
  }
  else {
    if (segment->flags & TH_FIN) {
    //  printf("[INFO] is fin\n");
      state->recv_fin = 1;
      state->ackno += 1;
      ctcp_send_ack(state);
      conn_output(state->conn, NULL, 0);
    }
    /* upate unacked_segments */
    update_unacked_segments(state, segment_ackno);
    free(segment);
  }

  if (state->recv_fin && state->sent_fin)
    if (state->segments->length==0 && state->unacked_segments->length==0) {
      ctcp_destroy(state);
  }
}

void ctcp_output(ctcp_state_t *state) {
  int available_space = conn_bufspace(state->conn);
  ll_node_t *traverse = ll_front(state->segments);
  int outputted = false;
  while (traverse) {
    ctcp_segment_t *segment = (ctcp_segment_t*)traverse->object;
    uint32_t segment_seqno = ntohl(segment->seqno);
    uint16_t data_len = ntohs(segment->len)- CTCP_HDR_SIZE;
    if (segment_seqno == state->ackno && data_len <= available_space) {
    //  printf("[INFO] data=%s, data_len=%d\n", segment->data, data_len);
      conn_output(state->conn, segment->data, data_len);
      outputted = true;
      available_space -= data_len;
      state->ackno += data_len;
      state->send_base = ntohl(segment->ackno);
      ll_node_t *traverse_next = traverse->next;          
      void *segment = ll_remove(state->segments, traverse);
      free(segment);
      traverse = traverse_next;
    }
    else
      break;
  }

  if (outputted)
    ctcp_send_ack(state);

}

void ctcp_timer() {
  ctcp_state_t *state = state_list;
  while (state) {
    ll_node_t *traverse = ll_front(state->unacked_segments);
    int destroy_state = false;
    while (traverse) {
      int cur_time = get_msec();
      ctcp_send_record_t *record = (ctcp_send_record_t*)(traverse->object);
      if (record->rt_count == 5) {
        destroy_state = true;
        break;
      }
      else if (cur_time - record->send_time >= state->rt_timeout) {
 	ctcp_send_segment(state, record->segment);
        record->send_time = cur_time;
        record->rt_count += 1;
      } 
      traverse = traverse->next;
    }

    state = state->next;
    if (destroy_state) 
      ctcp_destroy(state);
    
  }
}


