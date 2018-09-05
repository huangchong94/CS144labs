/******************************************************************************
 * ctcp.h
 * ------
 * Contains definitions for constants functions, and structs you will need for
 * the cTCP implementation. Implementations of the functions should be done in
 * ctcp.c.
 *
 *****************************************************************************/

#ifndef CTCP_H
#define CTCP_H

#include "ctcp_sys.h"

/**
 * Maximum segment data size.
 *
 * For stop-and-wait, advertise a window of MAX_SEG_DATA_SIZE.
 * For sliding window, advertise a window of n * MAX_SEG_DATA_SIZE, where n is
 * any integer specified by the -w flag.
 *
 * The maximum segment data size is the maximum number of bytes of DATA that can
 * be sent or received in a single cTCP segment. It does not include the
 * headers. A cTCP segment may be smaller than MAX_SEG_DATA_SIZE.
 *
 * A sliding window of size n * MAX_SEG_DATA_SIZE may have more than n segments,
 * if not all the segments are of the full MAX_SEG_DATA_SIZE in size.
 */
#define MAX_SEG_DATA_SIZE 1440

/**
 * cTCP flags.
 *
 * These are in HOST order. Make sure to convert to network-byte order when
 * needed. Check if a segment is an ACK by doing (flags & ACK).
 */
#define SYN ntohl(TH_SYN)
#define ACK ntohl(TH_ACK)
#define FIN ntohl(TH_FIN)


/**
 * cTCP configuration struct.
 *
 * Use these values to adjust your cTCP implementation accordingly.
 */
typedef struct {
  uint16_t recv_window;    /* Receive window size (in multiples of
                              MAX_SEG_DATA_SIZE) of THIS host. For Lab 1 this
                              value will be 1 * MAX_SEG_DATA_SIZE */
  uint16_t send_window;    /* Send window size (a.k.a. receive window size of
                              the OTHER host). For Lab 1 this value
                              will be 1 * MAX_SEG_DATA_SIZE */
  int timer;               /* How often ctcp_timer() is called, in ms */
  int rt_timeout;          /* Retransmission timeout, in ms */
} ctcp_config_t;

/**
 * Connection state.
 *
 * Stores per-connection information such as the current sequence number,
 * unacknowledged segments, etc.
 *
 * The definition can be found in ctcp.c. You should add to this to store other
 * fields you might need.
 */
struct ctcp_state;
typedef struct ctcp_state ctcp_state_t;


////////////////////////////////// YOUR CODE //////////////////////////////////

/**
 * Initialize state associated with a connection. This is called by the library
 * when a new connection is made. You should set up any fields you need to keep
 * track of segments being sent to and received from this connection.
 *
 * conn: Connection object associated with this connection. Is NULL if a
 *       connection to the server cannot be established. In this case, NULL
 *       should be returned. Memory management is handled by the starter code in
 *       ctcp_destroy().
 * cfg: cTCP configuration struct. Contains details about the window size,
 *      timeout interval, and timer frequency. Use the values in this struct
 *      (defined in ctcp.h) to adjust your timeouts, window sizes, etc.
 *      accordingly. You MUST free this struct when you are done with it!
 *
 * returns: Returns the state associated with this connection. If a connection
 *          cannot be established, returns NULL.
 */
ctcp_state_t *ctcp_init(conn_t *conn, ctcp_config_t *cfg);

/**
 * Destroys connection state for a connection. You should call this when all of
 * the following hold:
 *    - You have received a FIN from the other side.
 *    - You have read an EOF or error from your input (conn_input returned -1)
 *      and have sent a FIN to the other side.
 *    - All sent segments (including the FIN) have been acknowledged.
 *    - All received segments have been outputted.
 * Or:
 *    - The other side is unresponsive (after retransmitting the same segment 5
 *      times and still receiving no response).
 *
 * Free up any memory allocated for this connection.
 *
 * state: Connection state to destroy.
 */
void ctcp_destroy(ctcp_state_t *state);

/**
 * This is called if there is input to be read. To read the input, call
 * conn_input() with a buffer of the correct size. If no data is available,
 * conn_input() will return 0. ctcp_read() is called automatically by the
 * library when there is more input to read (so you never need to call it
 * yourself).
 *
 * conn_input() will return -1 when it reads an EOF. You should send a FIN to
 * the other side when this occurs. Then, you will need to destroy any
 * connection state once the conditions are satisfied (see ctcp_destroy()).
 *
 * Create a segment from the input and send it to the connection associated with
 * the passed in state (by calling conn_send()).
 *
 * state: State for the connection associated with this input. Get the
 *        associated connection object with state->conn.
 */
void ctcp_read(ctcp_state_t *state);

/**
 * This is called by the library when a segment is received. You should send
 * ACKs accordingly and output the segment's data to STDOUT if there is data.
 * To output, call on ctcp_output(), which you also must implement.
 *
 * The received segment MUST BE FREED after you are done with it.
 *
 * If you receive a FIN segment, you should output an EOF by calling
 * conn_output() with a length of 0. Then, you will need to destroy any
 * connection state once the conditions are satisfied (see ctcp_destroy()).
 *
 * state: Associated connection state.
 * segment: Segment received from the server. You should free this when you are
 *          done with it.
 * len: Length of the segment (including the headers). There might be extra
 *      padding so the received length might be larger than the length field in
 *      the segment header. The segment may have also been truncated (len is
 *      smaller than the length of the segment).
 */
void ctcp_receive(ctcp_state_t *state, ctcp_segment_t *segment, size_t len);

/**
 * Outputs cTCP segments associated with the given ctcp_state_t object. This
 * should be called by ctcp_receive() if a segment is ready to be outputted.
 *
 * Before outputting a segment, you will need to call conn_bufspace() to see
 * how many bytes can be outputted to STDOUT. If there is no room, ctcp_output()
 * will automatically be called by the library when there is. Call conn_output()
 * in order to actually output the segment. If you call conn_output() with more
 * data than conn_bufspace() says is available, not all of it may be written.
 *
 * You should flow control the sender by not acknowledging segments if there
 * is no buffer space available for conn_output().
 *
 * state: Associated connection state with the output.
 */
void ctcp_output(ctcp_state_t *state);

/**
 * Called periodically at specified rate (see the timer field in the
 * ctcp_config_t struct).
 *
 * You can use this timer to inspect segments and retransmit ones that have not
 * been acknowledged. Do not retransmit every segment every time the timer is
 * fired! A segment should only be retransmitted rt_timeout milliseconds after
 * it was last sent (also defined in the ctcp_config_t struct).
 *
 * After 5 retransmission attempts (so a total of 6 times) for a segment, you
 * should assume the other end of the connection is unresponsive and tear down
 * the connection (via a call to ctcp_destroy()).
 *
 * Note that this is called BEFORE ctcp_init() so state_list might be NULL.
 */
void ctcp_timer();

#endif /* CTCP_H */
