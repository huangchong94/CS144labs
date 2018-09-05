/******************************************************************************
 *                          |   Cardinal TCP v1.0   |
 *                          |   October 15, 2015    |
 *                          | <anjoola@anjoola.com> |
 *                          +-----------------------+
 * ctcp_sys_internal.c
 * -------------------
 * Contains the main functionality for cTCP. Converts cTCP to TCP and
 * vice-versa for interoperability. You do not need to look at or understand
 * this file.
 *****************************************************************************/

#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stddef.h>
#include <time.h>
#include <unistd.h>

#include "ctcp_sys_internal.h"
#include "ctcp_sys.h"

#define ASSERT_CLIENT_ONLY (assert(!SERVER))
#define ASSERT_SERVER_ONLY (assert(SERVER))
#define ASSERT_CONN (assert(!conn->delete_me))

static bool DEBUG = false;
static bool SERVER = false;

/** Configuration information for a client or server. */
struct config {
  int socket;                  /* Socket to send and receive out of */
  in_addr_t ip_addr;           /* IP address */
  int port;                    /* Port */
  struct sockaddr_in saddr;    /* Socket address */
  struct sockaddr_un sunaddr;  /* Unix socket */

  /* Client */
  conn_t *sconn;               /* Server connection details. */

  /* Server */
  conn_t *connections;         /* Connection details for clients connected
                                  to this server */
  char *program;               /* Program to start */
  int argc;                    /* Number of arguments to this program */
  char **argv;                 /* Array of arguments */
};

static struct config *config;
static ctcp_config_t *ctcp_cfg;

/** Whether or not a Unix socket is being used instead of a normal socket. */
static bool unix_socket = true;

/** Whether or not the server runs a program. */
static bool run_program = false;

/** Options for unreliable communications. */
static int seed = 144;
static int opt_drop = false;
static int opt_corrupt = false;
static int opt_delay = false;
static int opt_duplicate = false;

/** For tester, we only do the unreliability once, deterministically. This is
    set to true once it has occurred. */
static bool tester_did_unreliable = false;

/** Log file. */
int log_file = -1;

/** Port number of a new connection if a client just connected. Used to avoid
    logging ACK segments in response to a SYN+ACK. */
static int new_connection = 0;

/**
 * Polling configuration:
 *    0    STDIN
 *    1    STDOUT
 *    2    Network
 *    3... Program STDOUT/STDERR (if running as server)
 */
static struct pollfd *events;

/** When the last timer timeout occurred. */
static struct timespec last_timeout;

/** Number of clients connected. MAX_NUM_CLIENTS can be connected. */
static int num_connected = 0;

/** Main thread and thread for sending rests. */
static pthread_t thread_main;
static pthread_t thread_resets;
static bool handling_resets = false;


/////////////////////////////// HELPER FUNCTIONS //////////////////////////////

/**
 * Get the connections for the client or server.
 *
 * returns: A pointer to the start of the linked list of connections (for the
 *          server), or to the connection to the server (for the client).
 */
conn_t *get_connections() {
  if (SERVER)  return config->connections;
  else         return config->sconn;
}

/**
 * Set up the configuration for this host:
 *   - Create raw socket to communicate.
 *   - Initialize configuration struct
 *   - Bind to port/name so only relevant packets are received.
 *
 * port: Port to listen on.
 * returns: 0 on success, -1 otherwise.
 */
int do_config(char *port) {
  /* Create raw (Unix) socket. */
  int s;
  if (unix_socket)  s = socket(AF_UNIX, SOCK_DGRAM, 0);
  else              s = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
  if (s < 0) {
    fprintf(stderr, "[ERROR] Could not open socket (are you running "
                    "as sudo?)\n");
    return -1;
  }

  /* Make sure kernel knows IP header is included in packet so it doesn't add its
     own. For non-Unix socket only. */
  if (!unix_socket) {
    int one = 1;
    if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, (char *) &one, sizeof(one)) < 0) {
      fprintf(stderr, "[ERROR] Could not set IP_HDRINCL\n");
      return -1;
    }

    config->ip_addr = ip_from_self();
    if (config->ip_addr == 0) {
      fprintf(stderr, "[ERROR] Could not determine IP address\n");
      return -1;
    }
  }

  /* Other configuration. */
  config->port = atoi(port);
  config->socket = s;
  config->connections = NULL;

  /* Set up receive timeout. */
  struct timeval tv;
  tv.tv_sec = CONN_TIMEOUT;
  tv.tv_usec = 0;
  setsockopt(config->socket, SOL_SOCKET, SO_RCVTIMEO, (char *) &tv,
             sizeof(struct timeval));

  /* Bind socket to port/name so host receives only relevant messages. */
  struct sockaddr *addr;
  size_t size;
  if (unix_socket) {
    memset(&config->sunaddr, 0, sizeof(struct sockaddr_un));
    config->sunaddr.sun_family = AF_UNIX;
    sprintf(config->sunaddr.sun_path, "/%s", port);
    unlink(config->sunaddr.sun_path);

    addr = (struct sockaddr *) &config->sunaddr;
    size = sizeof(config->sunaddr);
  }
  else {
    config->saddr.sin_family = AF_INET;
    config->saddr.sin_addr.s_addr = config->ip_addr;
    config->saddr.sin_port = htons(config->port);

    addr = (struct sockaddr *) &config->saddr;
    size = sizeof(config->saddr);
  }

  if (bind(s, addr, size) < 0) {
    fprintf(stderr, "[ERROR] Could not bind to port %d\n", config->port);
    return -1;
  }

  /* Handle if previous connection(s) have not ended. Send RSTs to those
     hosts in a different thread. First create the reset thread. */
  thread_main = pthread_self();
  pthread_create(&thread_resets, NULL, send_resets, NULL);

  /* Wait for a bit. If still handling resets, wait. */
  sleep(RESET_THREAD_DURATION);
  while (handling_resets);

  /* Kill the thread. */
  pthread_cancel(thread_resets);
  pthread_join(thread_resets, NULL);
  fprintf(stderr, "done!\n");
  return 0;
}

/**
 * [Client only]
 * Setup the configuration for the server this client is connecting to:
 *   - Get server host and port.
 *   - Get address of server.
 *
 * server: Of the form server_host:server_port. The server to connect to.
 *         If no port is specified, defaults to port 80.
 * returns: 0 on success, -1 otherwise.
 */
int do_config_server(char *server) { ASSERT_CLIENT_ONLY;
  /* Parse server into its hostname and port. */
  char *host, *server_port_str, *_server = server;
  int server_port;
  host = strsep(&server, ":");
  if (server == NULL) {
    fprintf(stderr, "[ERROR] No port specified for server %s\n", host);
    return -1;
  }
  server_port_str = strsep(&server, ":");
  server_port = atoi(server_port_str);
  config->sconn = calloc(sizeof(conn_t), 1);
  conn_add(config->sconn);

  /* Get IP address of server. See if this is a server on the same machine. */
  in_addr_t dst_ip = ip_from_hostname(_server);
  if (dst_ip == 0)
    return -1;
  else if (dst_ip != LOCALHOST)
    unix_socket = false;

  /* Set up connection details. */
  int port = server_port == 0 ? DEFAULT_PORT : server_port;
  conn_setup(config->sconn, dst_ip, port, unix_socket);

  return 0;
}


///////////////////////////// PACKETS AND SEGMENTS ////////////////////////////

/**
 * Creates a TCP RST to a given address (in response to a TCP segment that was
 * sent.
 *
 * ip_dst: Destination IP address.
 * port_src: Source port.
 * port_dst: Destination port.
 * seqno: Sequence number of the packet.
 */
char *create_tcp_rst(in_addr_t ip_dst, uint16_t port_src, uint16_t port_dst,
                     uint32_t seqno) {
  /* Create the packet. */
  char *datagram = create_datagram(config->ip_addr, ip_dst, TCP_HDR_SIZE);
  iphdr_t *ip_hdr = (iphdr_t *) datagram;
  tcphdr_t *tcp_hdr = (tcphdr_t *) (datagram + IP_HDR_SIZE);

  /* TCP header. */
  tcp_hdr->th_sport = port_src;
  tcp_hdr->th_dport = port_dst;
  tcp_hdr->th_seq = seqno;
  tcp_hdr->th_ack = 0;
  tcp_hdr->th_off = TCP_HDR_SIZE / 4;
  tcp_hdr->th_flags = TH_RST;
  tcp_hdr->th_win = 0;
  tcp_hdr->th_sum = cksum_tcp(ip_hdr, 0);

  return datagram;
}

/**
 * Creates a TCP segment (including the IP header). The returned segment must
 * be freed.
 *
 * dst: A conn_t containing details for the destination.
 * flags: TCP flags.
 * data: Buffer containing the data payload.
 * len: Data length (should not include the size of the headers).
 *
 * returns: A TCP segment with the specified fields.
 */
char *create_tcp_seg(conn_t *dst, uint8_t flags, char *data, uint16_t len) {
  uint16_t tcp_seg_len = TCP_HDR_SIZE + len;
  char *datagram = create_datagram(config->ip_addr, dst->ip_addr, tcp_seg_len);
  iphdr_t *ip_hdr = (iphdr_t *) datagram;
  tcphdr_t *tcp_hdr = (tcphdr_t *) (datagram + IP_HDR_SIZE);

  /* Copy data over, if there is any. */
  if (len > 0 && data != NULL) {
    char *payload = (char *)((uint8_t *) tcp_hdr + TCP_HDR_SIZE);
    memcpy(payload, data, len);
  }

  uint16_t window = 0;
  if (!(flags & TH_RST))
    window = htons(ctcp_cfg->recv_window);

  /* TCP header. */
  tcp_hdr->th_sport = htons(config->port);
  tcp_hdr->th_dport = htons(dst->port);
  tcp_hdr->th_seq = htonl(dst->next_seqno);
  tcp_hdr->th_ack = htonl(dst->ackno);
  tcp_hdr->th_off = TCP_HDR_SIZE / 4;
  tcp_hdr->th_flags = flags;
  tcp_hdr->th_win = window;
  tcp_hdr->th_sum = 0;

  /* TCP checksum. */
  tcp_hdr->th_sum = cksum_tcp(ip_hdr, len);

  /* Update sequence numbers. */
  dst->seqno = dst->next_seqno;
  dst->next_seqno += len;

  return datagram;
}

/**
 * Converts a packet from a raw IP packet to a cTCP segment. If there is
 * padding, keep it. The resulting segment must be freed.
 *
 * src: A conn_t containing connection details of the segment's sender.
 * datagram: The raw IP packet.
 * actual_len: Actual length of packet received.
 * returns: A cTCP segment.
 */
ctcp_segment_t *convert_to_ctcp(conn_t *src, char *datagram, int actual_len) {
  iphdr_t *ip_hdr = (iphdr_t *) datagram;
  tcphdr_t *tcp_hdr = (tcphdr_t *) (datagram + IP_HDR_SIZE);
  char *payload = (char *)((uint8_t *) tcp_hdr + TCP_HDR_SIZE);

  /* Get actual lengths and allocate cTCP segment of correct size. */
  uint16_t data_len = ntohs(ip_hdr->tot_len) - FULL_HDR_SIZE;
  uint16_t len = data_len + sizeof(ctcp_segment_t);
  ctcp_segment_t *segment = calloc(len, 1);

  /* Set fields of cTCP segment. Convert sequence numbers to relative
     sequence numbers. */
  segment->seqno = htonl(ntohl(tcp_hdr->th_seq) - src->their_init_seqno);
  segment->ackno = htonl(ntohl(tcp_hdr->th_ack) - src->init_seqno);
  segment->len = htons(len);
  segment->flags = tcp_hdr->th_flags;
  segment->window = tcp_hdr->th_win;
  segment->cksum = 0;
  if (data_len > 0)
    memcpy(segment->data, payload, data_len);
  segment->cksum = cksum(segment, len);

  /* Find the difference in the given TCP checksum and the correct one. This
     difference is the same difference that should be added to the cTCP one.
     This will do the correct translation back to the cTCP checksum computed by
     the student (see convert_to_datagram). */
  uint16_t sum = tcp_hdr->th_sum;
  tcp_hdr->th_sum = 0;
  uint16_t correct_sum = cksum_tcp(ip_hdr, data_len);
  segment->cksum += (correct_sum - sum);
  return segment;
}

/**
 * Converts a segment from a cTCP segment to a raw IP packet. The resulting
 * packet must be freed.
 *
 * dst: A conn_t containing connection details of the packet's receiver.
 * segment: The cTCP segment.
 * len: Length of the cTCP segment (including the headers).
 * returns: A raw IP packet, NULL if it has an incorrect checksum.
 */
char *convert_to_datagram(conn_t *dst, ctcp_segment_t *segment, int len) {
  /* Create IP packet with TCP payload. */
  uint16_t tcp_pkt_len = len - sizeof(ctcp_segment_t) + TCP_HDR_SIZE;
  char *datagram = create_datagram(config->ip_addr, dst->ip_addr, tcp_pkt_len);
  iphdr_t *ip_hdr = (iphdr_t *) datagram;
  tcphdr_t *tcp_hdr = (tcphdr_t *) (datagram + IP_HDR_SIZE);

  /* Copy data over, if there is any. */
  uint16_t data_len = len - sizeof(ctcp_segment_t);
  if (data_len > 0 && segment->data != NULL) {
    char *payload = (char *)((uint8_t *) tcp_hdr + TCP_HDR_SIZE);
    memcpy(payload, segment->data, data_len);
  }

  /* TCP header. Convert relative sequence numbers to sequence numbers. */
  tcp_hdr->th_sport = htons(config->port);
  tcp_hdr->th_dport = htons(dst->port);
  tcp_hdr->th_seq = htonl(ntohl(segment->seqno) + dst->init_seqno);
  tcp_hdr->th_ack = htonl(ntohl(segment->ackno) + dst->their_init_seqno);
  tcp_hdr->th_off = TCP_HDR_SIZE / 4;
  tcp_hdr->th_flags = segment->flags;

  /* Need to add ACK to all segments if sending it to the web. */
  if (!run_program && !unix_socket)
    tcp_hdr->th_flags |= TH_ACK;
  tcp_hdr->th_win = segment->window;
  tcp_hdr->th_sum = 0;

  /* Add on the difference between the student's checksum and the correct
     checksum. If the difference is 0, then they computed the checksum
     correctly. Otherwise, an incorrect cTCP checksum will result in an
     incorrect TCP checksum. */
  uint16_t sum = segment->cksum;
  segment->cksum = 0;
  uint16_t correct_sum = cksum(segment, len);
  segment->cksum = sum;

  /* TCP checksum. Add on the difference between the correct checksum and the
     student's checksum. */
  tcp_hdr->th_sum = cksum_tcp(ip_hdr, data_len);
  tcp_hdr->th_sum += (correct_sum - sum);
  return datagram;
}

/**
 * Naive filtering. Host might receive many unwanted packets or leftover
 * packets from a previous session. We drop these packets.
 *
 * sockfd: Socket file descriptor.
 * buf: Buffer to receive data into.
 * len: Length of buffer and maximum size of data to receive.
 * flags: Flags for recv.
 * rconn: Return parameter. Pointer to the connection state associated with
 *        the sender of the packet.
 *
 * returns: Length of packet if packet wasn't dropped, 0 if no packet
 *          received, and -1 on failure.
 */
int recv_filter(int sockfd, void *buf, size_t len, int flags, conn_t **rconn) {
  int r = recv(sockfd, buf, len, flags);
  if (r < 0)
    return -1;

  if (r < FULL_HDR_SIZE)
    return 0;

  /* Is this packet to us? If not, ignore it. */
  iphdr_t *ip_hdr = (iphdr_t *) buf;
  tcphdr_t *tcp_hdr = (tcphdr_t *) (buf + IP_HDR_SIZE);
  if (tcp_hdr->th_dport != htons(config->port))
    return 0;

  /* A RST packet. End connection. */
  if (tcp_hdr->th_flags & TH_RST) {
    fprintf(stderr, "[ERROR] Server sent a RST! Closing connection.\n");
    exit(EXIT_FAILURE);
  }

  /* Otherwise a SYN or SYN-ACK? */
  if (tcp_hdr->th_flags & TH_SYN)
    return r;

  /* Some other packet from somewhere where we've already established a
     connection. Must have the correct source IP, port, and a sequence
     number we expect. */
  conn_t *conn = get_connections();
  while (conn != NULL) {
    if (conn->port == ntohs(tcp_hdr->th_sport) &&
        (unix_socket || (!unix_socket && conn->ip_addr == ip_hdr->saddr)) &&
        ntohl(tcp_hdr->th_seq) >= conn->their_init_seqno &&
        ntohl(tcp_hdr->th_ack) >= conn->init_seqno) {
      /* Return associated connection. */
      if (rconn != NULL)
        *rconn = conn;

      return r;
    }
    conn = conn->next;
  }

  return 0;
}

/**
 * Sends a packet out through the appropriate socket.
 *
 * dst: Destination connection object.
 * sockfd: Socket file descriptor.
 * buf: Data to send.
 * len: Length of data.
 * flags: Flags for sendto.
 *
 * returns: Number of bytes actually sent, or -1 if error.
 */
int send_pkt(conn_t *dst, int sockfd, const void *buf, size_t len, int flags) {
  struct sockaddr *addr;
  size_t size;

  /* Get the correct socket. */
  if (unix_socket) {
    addr = (struct sockaddr *) &dst->sunaddr;
    size = sizeof(dst->sunaddr);
  }
  else {
    addr = (struct sockaddr *) &dst->saddr;
    size = sizeof(dst->saddr);
  }

  return sendto(config->socket, buf, len, flags, addr, size);
}

/**
 * Send resets to previous connections, if they exist. We can tell if there are
 * lots of RSTs or ACKs being sent to us.
 */
void *send_resets(void *args) {
  fprintf(stderr, "[INFO] Cleaning up old connections... ");
  char buf[MAX_PACKET_SIZE];
  memset(buf, 0, MAX_PACKET_SIZE);
  int r;

  /* See if there are leftover packets. If so, send resets to them. */
  r = recv(config->socket, buf, MAX_PACKET_SIZE, 0);
  while (r > 0) {
    handling_resets = true;

    iphdr_t *ip_hdr = (iphdr_t *) buf;
    tcphdr_t *tcp_hdr = (tcphdr_t *) (buf + IP_HDR_SIZE);
    char *rst = create_tcp_rst(ip_hdr->saddr, tcp_hdr->th_dport,
                               tcp_hdr->th_sport, tcp_hdr->th_ack);

    /* Create connection object to send resets to. */
    conn_t conn;
    memset((void *) &conn, 0, sizeof(conn_t));
    conn_setup(&conn, ip_hdr->saddr, ntohs(tcp_hdr->th_sport), false);

    int s = sendto(config->socket, rst, FULL_HDR_SIZE, 0,
                   (struct sockaddr *) &conn.saddr, sizeof(conn.saddr));
    memset(buf, 0, MAX_PACKET_SIZE);
    free(rst);

    /* Could not send resets. Give up. */
    if (s < 0)
      break;

    /* Continue checking for more packets to send resets to. */
    handling_resets = false;
    r = recv(config->socket, buf, MAX_PACKET_SIZE, 0);
  }

  handling_resets = false;
  return NULL;
}

/**
 * Sends a TCP-connection related segment (SYN, FIN, etc.).
 *
 * dst: A conn_t object associated with the destination.
 * flags: TCP flags.
 *
 * returns: -1 if error, 0 otherwise.
 */
int send_tcp_conn_seg(conn_t *dst, int flags) {
  char *tcp_pkt = create_tcp_seg(dst, flags, NULL, 0);
  int r = send_pkt(dst, config->socket, tcp_pkt, FULL_HDR_SIZE, 0);
  free(tcp_pkt);

  if (r < 0) {
    fprintf(stderr, "[ERROR] Could not connect\n");
    return -1;
  }
  return 0;
}
inline int send_ack(conn_t *dst) {
  return send_tcp_conn_seg(dst, TH_ACK);
}
inline int send_rst(conn_t *dst) {
  return send_tcp_conn_seg(dst, TH_RST);
}
inline int send_syn(conn_t *dst) {
  return send_tcp_conn_seg(dst, TH_SYN);
}
inline int send_synack(conn_t *dst) {
  return send_tcp_conn_seg(dst, TH_SYN | TH_ACK);
}


////////////////////// CONNECTIONS AND SENDING/RECEIVING //////////////////////

/**
 * Add to the conn_t list.
 *
 * conn_list: Pointer to linked list of conn_t objects.
 * conn: The new conn_t to add.
 */
void conn_add(conn_t *conn) {
  conn_t *conn_list = get_connections();

  if (conn != conn_list) {
    conn->prev = &conn_list;
    conn->next = conn_list;

    if (conn_list)
      conn_list->prev = &conn->next;
  }
  conn->out_queue_tail = &conn->out_queue;

  if (SERVER)
    config->connections = conn;
  else
    config->sconn = conn;
}

/**
 * Checks how much space is available in STDOUT for output. conn_output can
 * only write as many bytes as reported by conn_bufspace.
 *
 * conn: The connection object.
 * returns: The number of bytes that can be written out.
 */
size_t conn_bufspace(conn_t *conn) {
  chunk_t *chunk;
  size_t used = 0;

  /* Count up how much output space already used. */
  for (chunk = conn->out_queue; chunk; chunk = chunk->next) {
    used += (chunk->size - chunk->used);
  }
  return used > MAX_BUF_SPACE ? 0 : MAX_BUF_SPACE - used;
}

/**
 * Drain the output queue.
 *
 * conn: Associated connection object.
 */
void conn_drain(conn_t *conn) {
  chunk_t *chunk;
  int w;
  bool outputted = false;
  events[STDOUT_FILENO].events &= ~POLLOUT;

  /* Already wrote an error, can't write anymore. */
  if (conn->wrote_err)
    return;

  /* Drain the output queue. Output as many chunks as possible. */
  while ((chunk = conn->out_queue)) {
    if (run_program)
      w = write(conn->stdin, chunk->buf + chunk->used,
                chunk->size - chunk->used);
    else
      w = write(STDOUT_FILENO, chunk->buf + chunk->used,
                chunk->size - chunk->used);

    if (w < 0) {
      if (errno != EAGAIN)
        conn->wrote_err = true;
      break;
    }
    outputted = true;
    chunk->used += w;

    /* Could not complete one chunk. Stop after this. */
    if (chunk->used < chunk->size) {
      events[STDOUT_FILENO].events |= POLLOUT;
      break;
    }
    conn->out_queue = chunk->next;

    /* Update pointers. */
    if (!conn->out_queue)
      conn->out_queue_tail = &conn->out_queue;
    free(chunk);
  }

  /* Error in outputting if already wrote EOF but still stuff in the output
     queue. */
  if (conn->wrote_eof && !conn->wrote_err && !conn->out_queue)
    conn->wrote_err = true;

  /* Output queue has space. Call student code. */
  if (outputted && !conn->delete_me)
    ctcp_output(conn->state);
}

/**
 * Removes a connection object from the conn_t list.
 *
 * conn: The conn_t to free.
 */
void conn_free(conn_t *conn) {
  /* Free up chunks. */
  chunk_t *chunk, *next_chunk;
  for (chunk = conn->out_queue; chunk; chunk = next_chunk) {
    next_chunk = chunk->next;
    free(chunk);
  }

  /* Adjust pointers. */
  if (conn->next)
    conn->next->prev = conn->prev;
  if (conn->prev)
    *conn->prev = conn->next;

  if (conn == get_connections()) {
    if (SERVER)
      config->connections = NULL;
    else
      config->sconn = NULL;
  }

  /* Close pipes to program, if it's running. */
  if (run_program) {
    close(conn->stdin);
    close(conn->stdout);
  }
  free(conn);
}

/**
 * Reads input that then needs to be put into segments to send off. Reads up to
 * to len bytes.
 *
 * conn: The connection object.
 * buf: Buffer to read
 * len: Maximum number of bytes to read.
 * returns: -1 if error or EOF, otherwise the actual number of bytes read. If
 *          no data is available, returns 0. The library will call ctcp_read
 *          again once data is available from conn_input.
 */
int conn_input(conn_t *conn, void *buf, size_t len) { ASSERT_CONN;
  int r;

  /* Check parameters. */
  if (conn == NULL || buf == NULL) {
    fprintf(stderr, "[ERROR] NULL parameters in conn_input\n");
    return -1;
  }

  /* Already read EOF. */
  if (conn->read_eof) {
    return -1;
  }

  /* Read from the appropriate place (STOUT of the associated program). */
  if (run_program)
    r = read(conn->stdout, buf, len);
  else if (unix_socket)
    r = read(STDIN_FILENO, buf, len);
  /* Add network-line endings if needed. */
  else {
    r = read(STDIN_FILENO, buf, len - 1);
    if (r > 0) {
      if (add_network_line_ending(!unix_socket, buf, r))
        r += 1;
      else
        r += read(STDIN_FILENO, buf + r, 1);
    }
  }

  /* Received EOF. In tester mode, we let the EOF character represent an EOF. */
  if (r == 0 || (r < 0 && errno != EAGAIN) ||
      ((test_debug_on || lab5_mode) && r > 0 && ((char *) buf)[0] == 0x1a)) {
    conn->read_eof = true;
    return -1;
  }
  /* No input. */
  else if (r < 0 && errno == EAGAIN) {
    r = 0;
  }

  return r;
}

/**
 * Schedules a connection object for removal.
 *
 * conn: The conn_t to remove.
 */
void conn_remove(conn_t *conn) {
  conn->delete_me = true;

  /* Log to tester that this connection has been removed (as a result to a call
     to ctcp_destroy). */
  if (test_debug_on) {
    fprintf(stderr, DEBUG_TEARDOWN);
  }
}

/**
 * Sends a cTCP segment to a destination associated with the provided
 * connection object.
 *
 * conn: Connection object.
 * segment: Pointer to cTCP segment to send.
 * len: Length of the segment (including the cTCP header and data).
 *
 * returns: The number of bytes actually sent, 0 if nothing was sent, -1 if
 *          there in an error.
 */
int conn_send(conn_t *conn, ctcp_segment_t *segment, size_t len) { ASSERT_CONN;
  /* Check parameters. */
  if (conn == NULL || segment == NULL) {
    fprintf(stderr, "[ERROR] NULL parameters in conn_send\n");
    return -1;
  }

  /* Make a copy of the segment first. */
  ctcp_segment_t *segment_copy = calloc(len, 1);
  memcpy(segment_copy, segment, len);

  /* Fork process off in order to do unreliability. Keep track of whether we
     are forked or not. */
  int fork_level = 0;
  bool am_i_forked = 0;

  /* Segment drop. Don't send the segment. */
  if ((test_debug_on && !tester_did_unreliable && opt_drop) ||
      (!test_debug_on && rand_percent(fork_level) < opt_drop)) {
    tester_did_unreliable = true;

    if (DEBUG) {
      fprintf(stderr, "[DEBUG] Dropping segment\n");
      print_hdr_ctcp(segment_copy);
    }
    free(segment_copy);
    return len;
  }

  /* Segment duplication. Fork another process to send the other segment. */
  if ((test_debug_on && !tester_did_unreliable && opt_duplicate) ||
      (!test_debug_on && rand_percent(fork_level) < opt_duplicate)) {
    tester_did_unreliable = true;

    if (DEBUG) {
      fprintf(stderr, "[DEBUG] Duplicating segment\n");
      print_hdr_ctcp(segment_copy);
    }
    if (fork() == 0) {
      am_i_forked = 1;
      fork_level++;
    }
  }

  /* Segment delay. Fork another process to delay the segment, and kill the
     current one. */
  if ((test_debug_on && !tester_did_unreliable && opt_delay) ||
       (!test_debug_on && rand_percent(fork_level) < opt_delay)) {
    tester_did_unreliable = true;

    if (DEBUG) {
      fprintf(stderr, "[DEBUG] Delaying segment\n");
      print_hdr_ctcp(segment_copy);
    }
    /* Forked process. Sleep for a bit. */
    if (fork() == 0) {
      am_i_forked = 1;
      fork_level++;
      sleep(rand() % 5);
    }
    /* Original process. */
    else {
      free(segment_copy);
      return len;
    }
  }

  /* Segment corruption. Flip bits in the segment after the TCP flags (to avoid
     corrupting the flags, which may cause problems). */
  bool do_corrupt = rand_percent(fork_level) < opt_corrupt;
  uint16_t data_length = len - sizeof(ctcp_segment_t) + sizeof(uint32_t);
  uint16_t rand_bit = rand() % (data_length * 8 - 1) +
                      (sizeof(ctcp_segment_t) - sizeof(uint32_t)) * 8;

  if ((test_debug_on && !tester_did_unreliable && opt_corrupt) ||
      (!test_debug_on && do_corrupt)) {
    tester_did_unreliable = true;

    if (DEBUG) {
      fprintf(stderr, "[DEBUG] Corrupting segment\n");
      print_hdr_ctcp(segment_copy);
    }
    flipbit(segment_copy, rand_bit);
  }

  uint16_t data_len = len - sizeof(ctcp_segment_t);
  uint16_t total_len = FULL_HDR_SIZE + data_len;

  if (log_file != -1 || test_debug_on) {
    log_segment(log_file, config->ip_addr, config->port, conn, segment_copy,
                len, true, unix_socket);
  }

  /* Convert from a cTCP segment to a real one and finally send the segment. */
  char *pkt = convert_to_datagram(conn, segment_copy, len);
  int n = send_pkt(conn, config->socket, pkt, total_len, 0);
  if (DEBUG) {
    fprintf(stderr, "[DEBUG] Sent segment\n");
    print_hdr_ctcp(segment_copy);
  }
  free(pkt);
  free(segment_copy);

  /* Kill forked process. */
  if (am_i_forked)
    exit(0);

  /* Return number of bytes sent. Need to subtract some because the return value
     is actually the size of the TCP segment instead of the cTCP segment. */
  if (n >= (long int)TCP_HDR_SIZE)
    return n - (TCP_HDR_SIZE + IP_HDR_SIZE - sizeof(ctcp_segment_t));
  return n;
}

/**
 * Writes a buffer to STDOUT or the program associated with this connection.
 * If called with a length of 0, an EOF is recorded.
 *
 * conn: The associated connection object.
 * buf: The buffer to output.
 * len: Number of bytes to write out.
 * returns: -1 if error, otherwise the number of bytes written out.
 */
int conn_output(conn_t *conn, const char *buf, size_t len) { ASSERT_CONN;
  /* If already wrote EOF, can't write more. */
  if (conn->wrote_eof)
    return 0;

  /* Writing EOF. */
  if (len == 0) {
    conn->wrote_eof = true;
    return 0;
  }

  /* If already wrote out an error, can't continue writing. */
  if (conn->wrote_err) {
    fprintf(stderr, "[ERROR] Attempting to write after error\n");
    return -1;
  }

  int left = len;
  int w = 0;

  /* See if there is actually room to output. */
  if (!conn_bufspace(conn))
    return 0;

  /* Nothing in the output queue. Output immediately to the appropriate
     interface. */
  if (!conn->out_queue) {
    if (run_program)
      w = write(conn->stdin, buf, len);
    else
      w = write(STDOUT_FILENO, buf, len);

    if (w < 0) {
      if (errno != EAGAIN) {
        if (run_program)
          fprintf(stderr, "[INFO] Program exited\n");
        conn->wrote_err = true;
        return -1;
      }
    }
    /* Write as much as possible. Keep track of how much was written. */
    else {
      buf += w;
      left -= w;
    }
  }

  /* Put the rest in an output queue. */
  if (left > 0) {
    chunk_t *chunk = calloc(offsetof(chunk_t, buf[left]), 1);
    chunk->next = NULL;
    chunk->size = left;
    chunk->used = 0;
    memcpy(chunk->buf, buf, left);

    /* Update pointers. */
    *conn->out_queue_tail = chunk;
    conn->out_queue_tail = &chunk->next;
  }

  /* If there is stuff in the queue, create an event. */
  if (conn->out_queue) {
    if (run_program)
      events[conn->stdin].events |= POLLOUT;
    else
      events[STDOUT_FILENO].events |= POLLOUT;
  }
  return len;
}

/**
 * [Client-only]
 * TCP handshake with server. This includes the SYN, SYN-ACK, and ACK segments.
 *
 * returns: A connection object if able to connect, NULL otherwise. This
 *          object must be freed.
 */
conn_t *tcp_handshake(void) { ASSERT_CLIENT_ONLY;
  char buf[MAX_PACKET_SIZE];

  /* Send a SYN segment to the server. */
  if (send_syn(config->sconn))
    exit(EXIT_FAILURE);

  /* Wait to receive SYN-ACK. */
  int r = recv_filter(config->socket, buf, MAX_PACKET_SIZE, 0, NULL);
  if (r <= 0)
    return NULL;

  tcphdr_t *synack = (tcphdr_t *) (buf + IP_HDR_SIZE);

  /* Set window size for the other host. */
  ctcp_cfg->send_window = ntohs(synack->window);

  /* If an ACK is received instead of a SYN-ACK, continue previous
     connection. Get sequence numbers from previous connection. */
  if ((synack->th_flags & TH_SYN) == 0) {
    config->sconn->init_seqno = ntohl(synack->th_ack) - 1;
    config->sconn->their_init_seqno = ntohl(synack->th_seq) - 1;

    config->sconn->next_seqno = config->sconn->init_seqno + 1;
    config->sconn->ackno = ntohl(synack->th_seq);
  }

  /* Otherwise, set new acknowledgement number and send ACK response */
  else {
    config->sconn->next_seqno++;
    config->sconn->their_init_seqno = ntohl(synack->th_seq);
    config->sconn->ackno = ntohl(synack->th_seq) + 1;
    send_ack(config->sconn);
  }

  return config->sconn;
}

/**
 * [Server only]
 * Handle a new connection from a client. Set up connection details and
 * initialize sequence numbers.
 *
 * pkt: The SYN segment from the client.
 * returns: The conn_t associated with the new connection.
 */
conn_t *tcp_new_connection(char *pkt) { ASSERT_SERVER_ONLY;
  /* Ignore if too many clients are connected. */
  if (num_connected >= MAX_NUM_CLIENTS) {
    fprintf(stderr, "[ERROR] Maximum number of clients (%d) reached\n",
            MAX_NUM_CLIENTS);
    return NULL;
  }
  num_connected++;

  iphdr_t *ip_hdr = (iphdr_t *) pkt;
  tcphdr_t *syn = (tcphdr_t *) (pkt + IP_HDR_SIZE);

  /* Set up connection details and add to list of connections. */
  conn_t *conn = calloc(sizeof(conn_t), 1);
  conn_setup(conn, ntohl(ip_hdr->saddr), ntohs(syn->th_sport), unix_socket);
  conn->their_init_seqno = ntohl(syn->th_seq);
  conn->ackno = conn->their_init_seqno + 1;
  conn_add(conn);

  /* Send a SYN-ACK to the client. */
  send_synack(conn);

  /* Get window size of the client. */
  ctcp_cfg->send_window = ntohs(syn->window);
  ctcp_config_t *config_copy = calloc(sizeof(ctcp_config_t), 1);
  memcpy(config_copy, ctcp_cfg, sizeof(ctcp_config_t));

  /* Student code. */
  ctcp_state_t *state = ctcp_init(conn, config_copy);
  conn->state = state;

  fprintf(stderr, "[INFO] Client connected\n");
  return conn;
}


///////////////////////////// SETUP AND MAIN LOOP /////////////////////////////

/**
 * [Server only]
 * Executes a new program upon client connection. When the client sends a
 * message to the server, it is forwarded to the STDIN of this program. The
 * STDOUT of the program is then passed through the server back to the client.
 *
 * conn: The conn_t associated with the client.
 */
void execute_program(conn_t *conn) { ASSERT_SERVER_ONLY;
  /* Create pipes to child. */
  int pipes[2][2];
  pipe(pipes[PARENT_READ_PIPE]);
  pipe(pipes[PARENT_WRITE_PIPE]);

  /* Fork child process to run program. */
  if (fork() == 0) {
    /* Duplicate fds so child and parent will share same pipe. */
    dup2(CHILD_READ_FD, STDIN_FILENO);
    dup2(CHILD_WRITE_FD, STDOUT_FILENO);
    dup2(CHILD_WRITE_FD, STDERR_FILENO);

    /* Close fds not required by child. */
    close(CHILD_READ_FD);
    close(CHILD_WRITE_FD);
    close(PARENT_READ_FD);
    close(PARENT_WRITE_FD);

    execvp(config->program, config->argv);
  }

  /* Continue parent process's execution. */
  else {
    /* Close fds not required by parent. */
    close(CHILD_READ_FD);
    close(CHILD_WRITE_FD);

    /* Store fds for communication with program later. */
    conn->stdin = PARENT_WRITE_FD;
    conn->stdout = PARENT_READ_FD;

    /* Start polling the stdout. */
    int id = NUM_POLL + num_connected - 1;
    struct pollfd *stdout = &events[id];
    stdout->fd = conn->stdout;
    async(stdout->fd);
    stdout->events = POLLIN | POLLHUP;
    conn->poll_fd = stdout;
  }
}

/**
 * Delete all connections.
 */
void delete_all_connections() {
  /* Delete connections if needed. */
  conn_t *conn, *next;
  for (conn = get_connections(); conn != NULL; conn = next) {
    next = conn->next;
    if (conn->delete_me)
      conn_free(conn);
  }
}

/**
 * Main loop. Handles the following:
 *   - Input from STDIN.
 *   - Messages from programs.
 *   - Packets from the socket.
 *   - Timeouts.
 */
void do_loop() {
  char buf[MAX_PACKET_SIZE];
  conn_t *conn = NULL;

  while (true) {
    memset(buf, 0, MAX_PACKET_SIZE);
    poll(events, NUM_POLL + num_connected,
         need_timer_in(&last_timeout, ctcp_cfg->timer));

    /* Input from stdin. Server will only send to most-recently connected
       client. */
    if (!run_program && events[STDIN_FILENO].revents & POLLIN) {
      conn = get_connections();

      if (conn != NULL)
        ctcp_read(conn->state);
    }

    /* See if we can output more. */
    if (events[STDOUT_FILENO].revents & (POLLOUT | POLLHUP | POLLERR)) {
      for (conn = get_connections(); conn; conn = conn->next) {
        conn_drain(conn);
      }
    }

    /* Poll for output received from running programs. Send to client
       client associated with this program instance. */
    if (run_program) {
      conn = get_connections();
      while (conn != NULL) {
        if (conn->poll_fd->revents & POLLIN) {
          ctcp_read(conn->state);
        }
        conn = conn->next;
      }
    }

    /* Receive packet on socket from other hosts. Ignore packets if they are
       not large enough or not for us. */
    if (events[2].revents & POLLIN) {
      conn = NULL;
      int len = recv_filter(config->socket, buf, MAX_PACKET_SIZE, 0, &conn);
      if (len >= FULL_HDR_SIZE) {
        tcphdr_t *tcp_hdr = (tcphdr_t *) (buf + IP_HDR_SIZE);

        /* Packet from an established connection. Pass to student code. */
        if (conn != NULL) {
          ctcp_segment_t *segment = convert_to_ctcp(conn, buf, len);
          len = len - FULL_HDR_SIZE + sizeof(ctcp_segment_t);

          /* Don't log or forward to student code if it's an ACK from a new
             connection. */
          if (tcp_hdr->th_sport == new_connection &&
              (segment->flags & TH_ACK) &&
              ntohl(segment->seqno) == 1 && ntohl(segment->ackno) == 1) {
            new_connection = 0;
            free(segment);
          }
          else {
            if (log_file != -1 || test_debug_on) {
              log_segment(log_file, config->ip_addr, config->port, conn,
                          segment, len, false, unix_socket);
            }
            ctcp_receive(conn->state, segment, len);
          }
        }

        /* New connection. */
        else if (tcp_hdr->th_flags & TH_SYN) {
          conn_t *conn = tcp_new_connection(buf);

          /* Start a new program associated with this client. */
          if (run_program && conn)
            execute_program(conn);
          new_connection = tcp_hdr->th_sport;
        }
      }
    }

    /* Check if timer is up. */
    if (need_timer_in(&last_timeout, ctcp_cfg->timer) == 0) {
      ctcp_timer();
      get_time(&last_timeout);
    }

    /* Delete connections if needed. */
    delete_all_connections();
  }
}

/**
 * Setup config for polling.
 */
void setup_poll() {
  /* Poll for input from stdin. */
  struct pollfd *stdin = &events[STDIN_FILENO];
  stdin->fd = STDIN_FILENO;
  stdin->events = POLLIN | POLLHUP | POLLERR;
  async(STDIN_FILENO);

  /* Poll stdout to do asynchronous output.. */
  struct pollfd *stdout = &events[STDOUT_FILENO];
  stdout->fd = STDOUT_FILENO;
  stdout->events = POLLOUT | POLLERR;
  async(STDOUT_FILENO);

  /* Poll for segments from the server. */
  struct pollfd *socket = &events[2];
  socket->fd = config->socket;
  socket->events = POLLIN | POLLHUP | POLLERR;
  async(config->socket);

  /* Used to detect if a network service has closed. */
  signal(SIGPIPE, SIG_IGN);
}

/**
 * Library teardown for a client.
 */
void end_client() {
  /* Make sure this is a client. */
  if (SERVER) {
    fprintf(stderr, "[INFO] Client disconnected\n");
    return;
  }

  delete_all_connections();
  close(config->socket);
  fprintf(stderr, "[INFO] Disconnected from server\n");
  exit(EXIT_SUCCESS);
}

/**
 * Start a client.
 *
 * server: String containing the server to connect to.
 * port: The port the client will run on.
 */
int start_client(char *server, char *port) {
  if (do_config_server(server) < 0 || do_config(port) < 0)
    return -1;

  /* Initialize connection with server. Go to student code. */
  conn_t *conn = tcp_handshake();
  ctcp_config_t *config_copy = calloc(sizeof(ctcp_config_t), 1);
  memcpy(config_copy, ctcp_cfg, sizeof(ctcp_config_t));
  ctcp_state_t *state = ctcp_init(conn, config_copy);
  if (state == NULL) {
    fprintf(stderr, "[ERROR] Could not connect to server!\n");
    return -1;
  }
  fprintf(stderr, "[INFO] Connected to server\n");
  config->sconn->state = state;

  setup_poll();
  do_loop();
  return 0;
}

/**
 * Start a server.
 *
 * port: The port the server will run on.
 * argc: Number of arguments to the program.
 * argv: Array containing arguments to program.
 */
int start_server(char *port, int argc, char *argv[]) {
  if (do_config(port) < 0)
    return -1;

  /* Keep track of program to start and its arguments. */
  if (argc - optind > 0) {
    run_program = true;
    config->program = argv[optind];
    config->argc = argc - optind;
    config->argv = argv + optind;
  }
  fprintf(stderr, "[INFO] Server started\n");

  setup_poll();
  do_loop();
  return 0;
}

/**
 * Prints out a usage message.
 *
 * progname: Name of the program.
 */
static void usage(char *progname) {
  fprintf(stderr,
    "\nUsage: %s\n"
    "   -c server_host:server_port  [client only]\n"
    "   -s                          [server only]\n"
    "   -p port\n"
    "   [-d]\n"
    "   [-w window_size]\n"
    "   [--seed seed]\n"
    "   [--drop drop_percent]\n"
    "   [--corrupt corrupt_percent]\n"
    "   [--delay delay_percent]\n"
    "   [--duplicate duplicate_percent]\n"
    "   [-- program arg1 arg2 ...]\n\n",
    progname
  );
  exit(1);
}

int main(int argc , char *argv[]) {
  /* Get program name. */
  char *progname = strrchr(argv[0], '/');
  if (progname)
    progname++;
  else
    progname = argv[0];

  /* Possible command-line arguments. */
  bool is_server = 0;
  bool is_client = 0;
  char *server = NULL;
  char *port_str = NULL;
  int port = -1;
  int window = 1;
  seed = time(NULL);
  test_debug_on = false;
  lab5_mode = false;
  struct option o[] = {
    { "debug", no_argument, NULL, 'd' },

    { "server", no_argument, NULL, 's' },
    { "client", required_argument, NULL, 'c' },
    { "port", required_argument, NULL, 'p' },
    { "window", required_argument, NULL, 'w' },

    { "seed", required_argument, NULL, 'e'},
    { "drop", required_argument, NULL, 'r' },
    { "corrupt", required_argument, NULL, 't' },
    { "delay", required_argument, NULL, 'y' },
    { "duplicate", required_argument, NULL, 'q' },
    { "logging", no_argument, NULL, 'l' },
    { "lab5", no_argument, NULL, 'f' },
    { NULL, 0, NULL, 0 }
  };

  /* Parse command-line arguments. */
  int opt;
  while ((opt = getopt_long(argc, argv, "dsc:p:w:r:t:y:q:lzf", o, NULL)) != -1) {
    switch (opt) {
    /* Debug statements on. */
    case 'd':
      DEBUG = true;
      break;
    /* Run as server. */
    case 's':
      is_server = true;
      break;
    /* Run as client and connect to a specified server. */
    case 'c':
      is_client = true;
      server = optarg;
      break;
    /* Port to run on. */
    case 'p':
      port = atoi(optarg);
      port_str = optarg;
      break;
    /* Window size. */
    case 'w':
      window = atoi(optarg);
      break;
    /* Seed for unreliability. */
    case 'e':
      seed = atoi(optarg);
      break;
    /* Segment drop. */
    case 'r':
      opt_drop = atoi(optarg);
      break;
    /* Segment corruption. */
    case 't':
      opt_corrupt = atoi(optarg);
      break;
    /* Segment delay. */
    case 'y':
      opt_delay = atoi(optarg);
      break;
    /* Segment duplicate. */
    case 'q':
      opt_duplicate = atoi(optarg);
      break;
    /* Turn logging on. */
    case 'l':
      log_file = 0;
      break;
    /* Turn logging data off for tester. */
    case 'z':
      test_debug_on = true;
      break;
    /* Lab 5 mode for handling FINs. */
    case 'f':
      lab5_mode = true;
      break;
    default:
      usage(progname);
      break;
    }
  }

  /* Seed RNG. */
  srand(seed);

  /* Validate arguments. */
  if ((is_client && is_server) || (!is_client && !is_server) || port <= 0) {
    usage(progname);
  }

  /* Construct log file if logging is turned on. Don't create a file if not
     logging data, since that is only used for testing purposes. */
  if (log_file == 0) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    char log_filename[40];
    memset(log_filename, 0, 40);
    snprintf(log_filename, sizeof(log_filename), "%d-%d.csv", (int) tv.tv_sec,
             port);
    log_file = open(log_filename, O_CREAT | O_TRUNC | O_WRONLY, 0666);
    write_log_header(log_file);
  }

  /* Global configuration. */
  struct config cc;
  config = &cc;

  /* CTCP config for students. */
  static ctcp_config_t cfg;
  ctcp_cfg = &cfg;
  cfg.recv_window = window * MAX_SEG_DATA_SIZE;
  cfg.send_window = window * MAX_SEG_DATA_SIZE;
  cfg.timer = TIMER_INTERVAL;
  cfg.rt_timeout = RT_INTERVAL;

  /* Used for polling later. */
  struct pollfd _events[NUM_POLL + MAX_NUM_CLIENTS];
  memset(_events, 0, sizeof(struct pollfd) * (NUM_POLL + MAX_NUM_CLIENTS));
  events = _events;

  /* Start client/server. */
  if (is_client) {
    if (start_client(server, port_str) < 0) {
      fprintf(stderr, "[ERROR] Client terminated\n");
      return 1;
    }
  }
  else if (is_server) {
    SERVER = true;
    if (start_server(port_str, argc, argv) < 0) {
      fprintf(stderr, "[ERROR] Server terminated\n");
      return 1;
    }
  }
  return 0;
}
