/******************************************************************************
 * ctcp_sys_internal.h
 * -------------------
 * Contains internal functions and definitions for the cTCP system. You do not
 * need to look at or understand this file.
 *
 *****************************************************************************/

#ifndef CTCP_SYS_INTERNAL_H
#define CTCP_SYS_INTERNAL_H

#include "ctcp.h"
#include "ctcp_sys.h"
#include "ctcp_utils.h"

#define DEFAULT_PORT 80
#define DEFAULT_TTL 64
#define TCP_MAX_PORT 65535
#define IP_ID 144

/** Localhost IP address in_addr_t. */
#define LOCALHOST 16777343

/** Maximum number of clients that can connect to the server. */
#define MAX_NUM_CLIENTS 10

/** Default number of things to poll (stdin, stdout, socket). */
#define NUM_POLL 3

/** Polling interval in milliseconds. */
#define POLL_INTERVAL 20

/** Length of time to wait while sending resets in seconds. */
#define RESET_THREAD_DURATION 1

/* Parameters to be changed by the tester. */

/** Retransmission interval in milliseconds. */
#define RT_INTERVAL 200

/** Timer interval (for calls to ctcp_timer) in milliseconds. */
#define TIMER_INTERVAL 40

/** Connection timeout interval in seconds. */
#define CONN_TIMEOUT 10

/////////////////////////////////// SYSTEM ////////////////////////////////////

/** Pipe created by parent process. */
#define PARENT_WRITE_PIPE 0
#define PARENT_READ_PIPE 1

#define READ_FD 0
#define WRITE_FD 1

/** File descriptors used by parent to read and write from child. */
#define PARENT_READ_FD (pipes[PARENT_READ_PIPE][READ_FD])
#define PARENT_WRITE_FD (pipes[PARENT_WRITE_PIPE][WRITE_FD])

/** File descriptors used by child to read and write to parent. */
#define CHILD_READ_FD (pipes[PARENT_WRITE_PIPE][READ_FD])
#define CHILD_WRITE_FD (pipes[PARENT_READ_PIPE][WRITE_FD])

/** Maximum space for buffering STDOUT for a given connection. */
#define MAX_BUF_SPACE 8192

/**
 * Chunk of output. Used to do asynchronous output. A connection will store
 * a queue of chunks to be outputted later.
 */
struct chunk {
  struct chunk *next;
  size_t size;              /* Size of chunk, in bytes */
  size_t used;              /* Amount of chunk already outputted */
  char buf[1];              /* Data */
} __attribute__((packed));
typedef struct chunk chunk_t;


/**
 * Makes a file descriptor asynchronous.
 *
 * fd: File descriptor to make asynchronous.
 * returns: -1 on failure, 0 on success.
 */
int async(int fd) {
  int flags;
  if ((flags = fcntl(fd, F_GETFL, 0)) < 0 ||
      fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
    return -1;
  }
  return 0;
}

/**
 * Gets the current time and stores it into the provided timespec object.
 *
 * ts: Timespec object to store result.
 */
void get_time(struct timespec *ts) {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  ts->tv_sec = tv.tv_sec;
  ts->tv_nsec = tv.tv_usec * 1000;
}

/**
 * Returns the number of milliseconds until the next timeout.
 *
 * last: The previous timeout.
 * interval: The timeout interval.
 */
long need_timer_in(const struct timespec *last, long interval) {
  long elapsed;
  struct timespec ts;

  get_time(&ts);
  elapsed = ts.tv_sec - last->tv_sec;
  if (elapsed > interval / 1000)
    return 0;

  elapsed = elapsed * 1000 + (ts.tv_nsec - last->tv_nsec) / 1000000;
  if (elapsed >= interval)
    return 0;
  return interval - elapsed;
}

/**
 * Send resets to previous connections, if they exist. We can tell if there are
 * lots of RSTs or ACKs being sent to us.
 */
void *send_resets(void *args);


/////////////////////////////////// SEGMENTS //////////////////////////////////

/** Salt used for rand_percent(). */
#define SALT (0x14400)

typedef struct iphdr iphdr_t;
typedef struct tcphdr tcphdr_t;

#define IP_HDR_SIZE sizeof(iphdr_t)
#define TCP_HDR_SIZE sizeof(tcphdr_t)
#define FULL_HDR_SIZE (sizeof(iphdr_t) + sizeof(tcphdr_t))

/** Maximum packet size (data and headers). */
#define MAX_PACKET_SIZE (1440 + sizeof(iphdr_t) + sizeof(tcphdr_t))

/** TCP pseudoheader, used in checksum calculations. */
struct tcp_pseudoheader {
  uint32_t src_addr;        /* Source address */
  uint32_t dst_addr;        /* Destination address */
  uint8_t placeholder;
  uint8_t protocol;         /* IP protocol (should be 6 for TCP) */
  uint16_t tcp_len;         /* TCP length */
  tcphdr_t tcp_hdr;         /* TCP header */
} __attribute__((packed));
typedef struct tcp_pseudoheader tcp_pseudoheader_t;

#define TCP_PSEUDOHDR_SIZE sizeof(tcp_pseudoheader_t)


/**
 * Add network-line endings to a string (converts from \n to \r\n).
 *
 * webserver: Whether or not communications is with a webserver. If so, adds
 *            extra line-endings. If not, does nothing.
 * buf: Buffer where the string is stored.
 * len: Length of data.
 * returns: Whether or not the network-line ending was added.
 */
bool add_network_line_ending(bool webserver, char *buf, size_t len) {
  if (!webserver || *(buf + len - 1) != '\n')
    return false;

  *(buf + len - 1) = '\r';
  *(buf + len) = '\n';
  *(buf + len + 1) = '\0';
  return true;
}

/**
 * Computes the TCP checksum. Returns the checksum in network order.
 *
 * packet: IP packet with a TCP payload.
 * len: Length of data (0 if no data and only TCP and IP headers).
 *
 * returns: The checksum in network order.
 */
uint16_t cksum_tcp(iphdr_t *packet, uint16_t len) {
  tcphdr_t *tcp_hdr = (tcphdr_t *) ((uint8_t *) packet + IP_HDR_SIZE);

  /* Construct pseudoheader. */
  tcp_pseudoheader_t *phdr = calloc(TCP_PSEUDOHDR_SIZE + len, 1);
  phdr->src_addr = packet->saddr;
  phdr->dst_addr = packet->daddr;
  phdr->protocol = IPPROTO_TCP;
  phdr->tcp_len = htons(TCP_HDR_SIZE + len);

  /* Append TCP segment and compute checksum. */
  memcpy(&(phdr->tcp_hdr), tcp_hdr, TCP_HDR_SIZE + len);
  uint16_t result = cksum(phdr, len + TCP_PSEUDOHDR_SIZE);
  free(phdr);
  return result;
}

/**
 * Creates an IP packet. The resulting packet must be freed by the caller.
 * Assumes arguments are in network order.
 *
 * src_ip: Source IP address.
 * dst_ip: Destination IP address.
 * len: Size of the IP packet payload.
 * returns: An IP packet of the specified length.
 */
char *create_datagram(in_addr_t src_ip, in_addr_t dst_ip, uint16_t len) {
  uint16_t total_len = IP_HDR_SIZE + len;
  char *datagram = calloc(total_len, 1);
  iphdr_t *ip_hdr = (iphdr_t *) datagram;

  /* IP header. */
  ip_hdr->ihl |= 5;
  ip_hdr->version |= 4;
  ip_hdr->tos = 0;
  ip_hdr->tot_len = htons(total_len);
  ip_hdr->id = htons(IP_ID);
  ip_hdr->frag_off = 0;
  ip_hdr->ttl = DEFAULT_TTL;
  ip_hdr->protocol = IPPROTO_TCP;
  ip_hdr->check = 0;
  ip_hdr->saddr = src_ip;
  ip_hdr->daddr = dst_ip;

  /* IP checksum. */
  ip_hdr->check = cksum(datagram, IP_HDR_SIZE);
  return datagram;
}

/**
 * Flips a bit in a segment.
 *
 * segment: The segment.
 * bit: The bit to flip.
 */
void flipbit(const void *segment, size_t bit) {
  char *data = ((char *) segment);
  unsigned int mask = 1 << (bit % 8);
  data[bit / 8] ^= mask;
}

/**
 * Returns a random percentage between 0 and 100.
 *
 * level: The fork level (used in computing the random value).
 * returns: A random percentage.
 */
int rand_percent(int level) {
  return (rand() + (level * SALT)) % 100;
}


////////////////////////// ADDRESSES AND CONNECTIONS //////////////////////////

/** Ethernet interface prefix to determine the client's own IP address. */
#define ETH_INTERFACE "eth"

/** Connection details for a host connected to the current host. */
struct conn {
  in_addr_t ip_addr;           /* IP address */
  int port;                    /* Port */
  struct sockaddr_in saddr;    /* Socket address */
  struct sockaddr_un sunaddr;  /* Unix socket */
  ctcp_state_t *state;         /* Connection state */

  uint32_t init_seqno;         /* My initial sequence number */
  uint32_t their_init_seqno;   /* Their initial sequence number */

  uint32_t seqno;              /* Current sequence number */
  uint32_t next_seqno;         /* Sequence number of next segment to send */
  uint32_t ackno;              /* Current ack number */

  int stdin;                   /* STDIN for the program */
  int stdout;                  /* STDOUT for the program */
  struct pollfd *poll_fd;      /* Used for polling for output from program */

  bool read_eof;               /* EOF read from STDIN */
  bool wrote_eof;              /* EOF wrote to STDOUT */
  bool wrote_err;              /* Error writing to STDOUT */
  bool delete_me;              /* Whether or not to delete this object. */

  chunk_t *out_queue;          /* Queue for output to STDOUT */
  chunk_t **out_queue_tail;    /* End of the output queue */

  struct conn *next;           /* Linked list of connections */
  struct conn **prev;
};
typedef struct conn conn_t;


/**
 * Add to the conn_t list.
 *
 * conn_list: Pointer to linked list of conn_t objects.
 * conn: The new conn_t to add.
 */
void conn_add(conn_t *conn);

/**
 * Set up a conn_t object with the right values.
 *
 * conn: The conn_t object.
 * ip_addr: IP address associated with this object.
 * port: Port associated with this object.
 * unix_socket: Whether or not this connection is for a Unix socket.
 */
void conn_setup(conn_t *conn, in_addr_t ip_addr, int port, bool unix_socket) {
  /* Set up IP address and port. */
  conn->ip_addr = ip_addr;
  conn->port = port;

  /* Socket address. Could be a Unix socket. */
  if (unix_socket) {
    memset(&conn->sunaddr, 0, sizeof(struct sockaddr_un));
    conn->sunaddr.sun_family = AF_UNIX;
    sprintf(conn->sunaddr.sun_path, "/%d", port);
  }
  else {
    conn->saddr.sin_family = AF_INET;
    conn->saddr.sin_addr.s_addr = ip_addr;
  }

  /* Random initial sequence number. */
  conn->init_seqno = rand();

  /* Other sequence numbers needed for connection setup and teardown. */
  conn->seqno = 0;
  conn->next_seqno = conn->init_seqno;
  conn->ackno = 0;
}

/**
 * Gets the client's own IP address.
 *
 * returns: An in_addr_t containing the IP address, or 0 if it cannot be found.
 *          Result is in network-order.
 */
in_addr_t ip_from_self(void) {
  struct ifaddrs *addrs = NULL, *iface;
  in_addr_t ip_addr = 0;
  getifaddrs(&addrs);

  /* Need to find the IP address from the correct interface. */
  char *correct_iface = ETH_INTERFACE;
  char check_iface[100];
  memset(check_iface, 0, 100);

  /* Go through each interface. */
  for (iface = addrs; iface != NULL; iface = iface->ifa_next) {
    if (iface->ifa_addr && iface->ifa_addr->sa_family == AF_INET) {
      /* Check if this is from the correct interface. */
      memcpy(check_iface, iface->ifa_name, strlen(iface->ifa_name) - 1);
      if (strcmp(check_iface, correct_iface) != 0)
        continue;

      ip_addr = ((struct sockaddr_in *) iface->ifa_addr)->sin_addr.s_addr;
    }
  }
  freeifaddrs(addrs);
  return ip_addr;
}

/**
 * Gets the IP address associated with a given hostname.
 *
 * hostname: The hostname to connect to (e.g. "www.google.com").
 *
 * returns: An ip_addr containing the IP address, or 0 if it cannot be found.
 *          Result is in network-order.
 */
in_addr_t ip_from_hostname(char *hostname) {
  /* Entry for the provided host. */
  char ip[INET_ADDRSTRLEN];
  struct hostent *entry;
  struct in_addr **addr_list;
  int i;

  /* Could not find a host with the given name. */
  if ((entry = gethostbyname(hostname)) == NULL) {
    fprintf(stderr, "[ERROR] Could not resolve %s!\n", hostname);
    return 0;
  }

  /* Get the first IP address from the found entry. */
  else {
    addr_list = (struct in_addr **) entry->h_addr_list;
    for (i = 0; addr_list[i] != NULL; i++) {
      strcpy(ip, inet_ntoa(*addr_list[i]));
    }
    return inet_addr(ip);
  }
}


/////////////////////////////////// LOGGING ////////////////////////////////////

#define LOG_SIZE (4 * MAX_SEG_DATA_SIZE)
#define LOG_ENTRY_SIZE 20
#define ADDR_FORMAT_STR "%s\t%d\t%s\t%d\t"
#define LOCALHOST_STR "localhost"

/** Headers for the log file. */
#define LOG_HEADERS "Timestamp\tSource IP\tSource Port\tDestination IP\tDestination Port\tSequence Number\tAcknowledgement Number\tLength\tFlags\tWindow\tChecksum\tData\n"

/** Debug messages for tester. */
#define DEBUG_TEARDOWN "###teardown###\n"

/**
 * Format the IP addresses and ports for the logger into the provided buffer.
 *
 * ip_addr: The logger's IP address.
 * port: The logger's port.
 * conn: The other's connection details.
 * is_sent_segment: Whether or not this is logging a segment sent by the logger.
 * is_unix_socket: Whether or not the connection is via a Unix socket.
 * buf: Buffer to write formatted IP addresses and ports.
 */
void format_addresses(in_addr_t ip_addr, int port, conn_t *conn,
                      bool is_sent_segment, bool is_unix_socket, char *buf) {
  if (!is_unix_socket) {
    char this_ip_addr[INET_ADDRSTRLEN];
    char other_ip_addr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip_addr, this_ip_addr, 100);
    inet_ntop(AF_INET, &(conn->ip_addr), other_ip_addr, 100);

    if (is_sent_segment) {
      snprintf(buf, 5 * LOG_ENTRY_SIZE, ADDR_FORMAT_STR, this_ip_addr, port,
               other_ip_addr, conn->port);
    }
    else {
      snprintf(buf, 5 * LOG_ENTRY_SIZE, ADDR_FORMAT_STR, other_ip_addr,
               conn->port, this_ip_addr, port);
    }
  }

  /** Just print "localhost" for Unix sockets. */
  else {
    if (is_sent_segment) {
      snprintf(buf, 5 * LOG_ENTRY_SIZE, ADDR_FORMAT_STR, LOCALHOST_STR, port,
               LOCALHOST_STR, conn->port);
    }
    else {
      snprintf(buf, 5 * LOG_ENTRY_SIZE, ADDR_FORMAT_STR, LOCALHOST_STR,
               conn->port, LOCALHOST_STR, port);
    }
  }
}

/**
 * Creates a hex dump of data.
 *
 * from: Data to create hex dump.
 * to: Location to write output of dump.
 * len: Length of data.
 */
void hex_dump(unsigned char *from, char *to, int len) {
  snprintf(to, 2, "\t");
  to++;

  /* Loop through all bytes in the data. */
  int i;
  for (i = 0; i < len; i++) {
    snprintf(to + i * 3, 4, "%02x ", from[i]);
  }
  snprintf(to + i * 3, 2, "\n");
}

/**
 * Logs a segment sent or received. Logged output is of the form:
 *    time fromIP fromPort toIP toPort seqno ackno len flags window cksum data
 *
 * file: File to output to.
 * ip_addr: The logger's IP address.
 * port: The logger's port.
 * conn: The other's connection details.
 * segment: Segment to log.
 * len: Length of the segment, including headers.
 * is_sent_segment: Whether or not this is logging a segment sent by the logger.
 * is_unix_socket: Whether or not the connection is via a Unix socket.
 */
void log_segment(int file, in_addr_t ip_addr, int port, conn_t *conn,
                 ctcp_segment_t *segment, uint16_t len, bool is_sent_segment,
                 bool is_unix_socket) {
  /* Create output buffer and write IP addresses and ports. */
  char buf[LOG_SIZE];
  memset(buf, 0, LOG_SIZE);

  /* Timestamp. */
  snprintf(buf, LOG_ENTRY_SIZE, "%lu\t", current_time());

  /* Source and destination. */
  format_addresses(ip_addr, port, conn, is_sent_segment, is_unix_socket,
                   buf + strlen(buf));

  /* Sequence number, ack number, length. */
  snprintf(buf + strlen(buf), 5 * LOG_ENTRY_SIZE, "%d\t%d\t%d\t",
           ntohl(segment->seqno), ntohl(segment->ackno), ntohs(segment->len));

  /* TCP flags. */
  if (segment->flags & TH_SYN)
    snprintf(buf + strlen(buf), 5, "SYN ");
  if (segment->flags & TH_ACK)
    snprintf(buf + strlen(buf), 5, "ACK ");
  if (segment->flags & TH_FIN)
    snprintf(buf + strlen(buf), 5, "FIN ");

  /* Window and checksum. */
  snprintf(buf + strlen(buf), LOG_ENTRY_SIZE, "\t%d\t0x%x",
           ntohs(segment->window), segment->cksum);

  /* Data. */
  if (!test_debug_on) {
    hex_dump((unsigned char *) segment->data,
             buf + strlen(buf),
             ntohs(segment->len) - sizeof(ctcp_segment_t));
    write(file, buf, strlen(buf));
  }
  /* Log data for the tester. */
  else {
    fprintf(stderr, "!!!%s!!!\n", buf);
  }
}

/**
 * Write out the headers to the log file.
 *
 * file: The log file.
 */
void write_log_header(int file) {
  write(file, LOG_HEADERS, strlen(LOG_HEADERS));
}


//////////////////////////////////// DEBUG ////////////////////////////////////

/**
 * Prints out an IP address as a string from an in_addr.
 *
 * address: in_addr to print.
 */
void print_addr_ip(in_addr_t address) {
  char buf[INET_ADDRSTRLEN];
  if (inet_ntop(AF_INET, &address, buf, 100) == NULL)
    fprintf(stderr, "[ERROR] Could not convert address to print\n");
  else
    fprintf(stderr, "%s\n", buf);
}

/**
 * Prints out an IP address from an integer value.
 *
 * ip: The integer value of the IP address.
 */
void print_addr_ip_int(uint32_t ip) {
  uint32_t cur_octet = ip >> 24;
  fprintf(stderr, "%d.", cur_octet);
  cur_octet = (ip << 8) >> 24;
  fprintf(stderr, "%d.", cur_octet);
  cur_octet = (ip << 16) >> 24;
  fprintf(stderr, "%d.", cur_octet);
  cur_octet = (ip << 24) >> 24;
  fprintf(stderr, "%d\n", cur_octet);
}

/**
 * Prints out the fields in an IP header. Assumes packet is in network-order.
 *
 * buf: The IP packet.
 */
void print_hdr_ip(uint8_t *buf) {
  iphdr_t *ip_hdr = (iphdr_t *) buf;
  fprintf(stderr, "+-----------------------------+\n");
  fprintf(stderr, "IP HEADER\n");
  fprintf(stderr, "  version: %d\n", ip_hdr->version);
  fprintf(stderr, "  header length: %d\n", ip_hdr->ihl);
  fprintf(stderr, "  type of service: %d\n", ip_hdr->tos);
  fprintf(stderr, "  length: %d\n", ntohs(ip_hdr->tot_len));
  fprintf(stderr, "  id: %d\n", ntohs(ip_hdr->id));

  if (ntohs(ip_hdr->frag_off) & IP_DF)
    fprintf(stderr, "  fragment flag: DF\n");
  else if (ntohs(ip_hdr->frag_off) & IP_MF)
    fprintf(stderr, "  fragment flag: MF\n");
  else if (ntohs(ip_hdr->frag_off) & IP_RF)
    fprintf(stderr, "  fragment flag: R\n");

  fprintf(stderr, "  fragment offset: %d\n", ntohs(ip_hdr->frag_off) & IP_OFFMASK);
  fprintf(stderr, "  TTL: %d\n", ip_hdr->ttl);
  fprintf(stderr, "  protocol: %d\n", ip_hdr->protocol);

  /* Keep checksum in network-byte order. */
  fprintf(stderr, "  checksum: %x\n", ip_hdr->check);
  fprintf(stderr, "  source: ");
  print_addr_ip_int(ntohl(ip_hdr->saddr));
  fprintf(stderr, "  destination: ");
  print_addr_ip_int(ntohl(ip_hdr->daddr));
}

/**
 * Prints out the fields in a TCP header. Assumes segment is in network-order.
 *
 * buf: The TCP segment.
 */
void print_hdr_tcp(uint8_t *buf) {
  tcphdr_t *tcp_hdr = (tcphdr_t *) buf;
  fprintf(stderr, "+-----------------------------+\n");
  fprintf(stderr, "TCP HEADER\n");
  fprintf(stderr, "  source port: %d\n", ntohs(tcp_hdr->th_sport));
  fprintf(stderr, "  destination port: %d\n", ntohs(tcp_hdr->th_dport));
  fprintf(stderr, "  seq number: %d\n", ntohl(tcp_hdr->th_seq));
  fprintf(stderr, "  ack number: %d\n", ntohl(tcp_hdr->th_ack));

  fprintf(stderr, "  flags: ");
  if (tcp_hdr->th_flags & TH_SYN)
    fprintf(stderr, "SYN ");
  if (tcp_hdr->th_flags & TH_ACK)
    fprintf(stderr, "ACK ");
  if (tcp_hdr->th_flags & TH_FIN)
    fprintf(stderr, "FIN ");
  if (tcp_hdr->th_flags & TH_RST)
    fprintf(stderr, "RST ");
  fprintf(stderr, "\n");

  fprintf(stderr, "  window size: %d\n", ntohs(tcp_hdr->th_win));
  /* Keep checksum in network-byte order. */
  fprintf(stderr, "  checksum: %x\n", tcp_hdr->th_sum);
}

/**
 * Prints out all headers.
 *
 * buf: The IP packet.
 */
void print_hdrs(void *buf, uint32_t length) {
  /* IP packet. */
  int min_length = IP_HDR_SIZE;
  if (length < min_length) {
    fprintf(stderr, "[ERROR] Failed to print IP header, insufficient length\n");
    return;
  }
  print_hdr_ip(buf);

  /* TCP segment. */
  iphdr_t *ip_hdr = (iphdr_t *) buf;
  uint8_t ip_proto = ip_hdr->protocol;
  if (ip_proto == IPPROTO_TCP) {
    min_length += IP_HDR_SIZE;
    if (length < min_length) {
      fprintf(stderr, "[ERROR] Failed to print TCP header, "
                      "insufficient length\n");
      return;
    }
    print_hdr_tcp(buf + IP_HDR_SIZE);
  }
}

#endif /* CTCP_SYS_INTERNAL_H */
