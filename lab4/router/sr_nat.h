
#ifndef SR_NAT_TABLE_H
#define SR_NAT_TABLE_H

#include <inttypes.h>
#include <time.h>
#include <pthread.h>
#include "sr_protocol.h"

#define OUTBOUND 1
#define INBOUND  0 

#define ILEGAL  -1
#define SYN_SENT 0
#define SYN_RCVD 1
#define ESTAB    2
#define CLOSING  3
#define CLOSED   4

typedef enum {
  nat_mapping_icmp,
  nat_mapping_tcp
  /* nat_mapping_udp, */
} sr_nat_mapping_type;

struct sr_nat_connection {
  uint32_t ip_dst;
  uint16_t port_dst;
  uint8_t state;
  time_t last_updated;
  struct sr_nat_connection *next;
};

struct sr_nat_mapping {
  sr_nat_mapping_type type;
  uint32_t ip_int; /* internal ip addr */
  uint32_t ip_ext; /* external ip addr */
  uint16_t aux_int; /* internal port or icmp id */
  uint16_t aux_ext; /* external port or icmp id */
  time_t last_updated; /* use to timeout mappings */
  struct sr_nat_connection *conns; /* list of connections. null for ICMP */
  uint16_t conn_count;
  struct sr_nat_mapping *next;
};

struct sr_pkt_list {
  uint8_t *buf;
  uint16_t len;
  time_t added;
  struct sr_pkt_list *next;
};

struct sr_nat {
  /* add any fields here */
  struct sr_nat_mapping *mappings;
  struct sr_pkt_list *syn_pkts;    /* unsolicited inbound */
  uint32_t mapping_count;
  struct sr_instance *sr;
  uint16_t icmp_timeout;
  uint16_t tcp_e_timeout;
  uint16_t tcp_t_timeout;

  /* threading */
  pthread_mutex_t lock;
  pthread_mutexattr_t attr;
  pthread_attr_t thread_attr;
  pthread_t thread;
};


int   sr_nat_init(struct sr_nat *nat);     /* Initializes the nat */
int   sr_nat_destroy(struct sr_nat *nat);  /* Destroys the nat (free memory) */
void *sr_nat_timeout(void *nat_ptr);  /* Periodic Timout */

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type );

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type );

/* Insert a new mapping into the nat's mapping table.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type );

struct sr_nat_mapping *sr_nat_lookup_or_insert_icmp_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int);

int sr_nat_modify_icmp(struct sr_nat *nat, struct sr_ip_hdr *ip_hdr, uint8_t outbound);

int sr_nat_modify_tcp(struct sr_nat *nat, uint8_t *packet, uint16_t len, uint8_t outbound);

#endif
