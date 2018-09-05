/******************************************************************************
 * ctcp_sys.h
 * ----------
 * Contains definitions for system and connection-related functions such as
 * reading input, writing output, sending a segment to a connection, etc.
 *
 * Implementations can be found in ctcp_sys_internal.c. You won't need to look
 * at the implementations in order to understand and do the assignment.
 *
 *****************************************************************************/

#ifndef CTCP_SYS_H
#define CTCP_SYS_H

#include <assert.h>
#include <fcntl.h>
#include <getopt.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>

/** Connection object. Used to identify the receiver of sent segments.
    Definition can be found in ctcp_sys_internal.c. */
typedef struct conn conn_t;
struct conn;

/**
 * cTCP segment.
 *
 * Make sure fields are in network-byte order when sending.
 */
typedef struct ctcp_segment {
  uint32_t seqno;        /* Sequence number (in bytes) */
  uint32_t ackno;        /* Acknowledgment number (in bytes) */
  uint16_t len;          /* Total segment length in bytes (including headers) */
  uint32_t flags;        /* TCP flags */
  uint16_t window;       /* Window size, in bytes */
  uint16_t cksum;        /* Checksum */
  char data[];           /* Pointer to start of data. Takes up no space in the
                            struct unless allocated; sizeof(ctcp_segment_t)
                            does not include this field */
} ctcp_segment_t;


/**
 * Call on this to read input locally to be put into segments that will be sent
 * to the destination specified by conn. Reads up to len bytes into the provided
 * buffer.
 *
 * conn: Connection object to identify the eventual destination of this input.
 * buf: Buffer to read into.
 * len: Maximum number of bytes to read. The buffer passed in must be large
 *      enough or an error/segmentation fault might occur.
 * returns: -1 if error or EOF, otherwise the actual number of bytes read. If
 *          no data is available, returns 0. The library will call ctcp_read()
 *          at some point once data is available from conn_input().
 */
int conn_input(conn_t *conn, void *buf, size_t len);

/**
 * Call on this to send a cTCP segment to a destination associated with the
 * provided connection object.
 *
 * If conn_send() returns a number smaller than what you expect, it's up to
 * you as to how you want to handle it. For example, you can choose to ignore it
 * and wait for a retranmission timeout to resend a segment.
 *
 * conn: Connection object.
 * segment: Pointer to cTCP segment to send.
 * len: Total length of the segment (including the cTCP header and data).
 *
 * returns: The number of bytes actually sent, 0 if nothing was sent, or -1 if
 *          there was an error.
 */
int conn_send(conn_t *conn, ctcp_segment_t *segment, size_t len);

/**
 * Call on this to produce output from the segments you have received from the
 * associated connection. This will either write output to STDOUT or to the
 * running service (if running network services on the server for Lab 2).
 *
 * Before calling conn_output(), you should first call conn_bufspace() to check
 * how much space is available for output. If you call conn_output() with more
 * data than conn_bufspace() says is available, not all of it may be written.
 *
 * Call this with a length of 0 to signal an EOF.
 *
 * If conn_output() returns -1, it's up to you as to how you want to handle it.
 * For example, you could just tear down the connection, since you can no longer
 * output any data.
 *
 * conn: The associated connection object that sent the segment.
 * buf: The buffer containing the output.
 * len: Number of bytes to write out.
 * returns: -1 if error, otherwise the number of bytes written out.
 */
int conn_output(conn_t *conn, const char *buf, size_t len);

/**
 * Checks how much space is available in STDOUT for output. conn_output() can
 * only write as many bytes as reported by conn_bufspace(). If you write out
 * fewer bytes than what conn_bufspace() reports available, then
 * conn_bufspace() is guaranteed to return a non-zero value the next time you
 * call it (meaning that there is still room to write out more).
 *
 * conn: The connection object.
 * returns: The number of bytes that can be written out.
 */
size_t conn_bufspace(conn_t *conn);

/**
 * Used to remove a connection object. This is already called on in the starter
 * code in ctcp_destroy(), so you do not need to add calls to it.
 *
 * conn: The conn_t object to remove.
 */
void conn_remove(conn_t *conn);


/** Whether or not the tester's debugging is turned on. You can ignore this. */
bool test_debug_on;

/** Whether or not to use in Lab 5 mode. You can ignore this. */
bool lab5_mode;

/**
 * Library teardown for a client. You can ignore this.
 */
void end_client();

#endif /* CTCP_SYS_H */
