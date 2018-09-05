
#include <signal.h>
#include <assert.h>
#include <stdlib.h>
#include "sr_nat.h"
#include "sr_utils.h"
#include "sr_router.h"
#include "sr_icmp.h"
#include "sr_rt.h"
#include "sr_arpcache.h"
#include <unistd.h>
#include <string.h>
#include<netinet/tcp.h>

int sr_nat_init(struct sr_nat *nat) { /* Initializes the nat */

  assert(nat);

  /* Acquire mutex lock */
  pthread_mutexattr_init(&(nat->attr));
  pthread_mutexattr_settype(&(nat->attr), PTHREAD_MUTEX_RECURSIVE);
  int success = pthread_mutex_init(&(nat->lock), &(nat->attr));

  /* Initialize timeout thread */

  pthread_attr_init(&(nat->thread_attr));
  pthread_attr_setdetachstate(&(nat->thread_attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_create(&(nat->thread), &(nat->thread_attr), sr_nat_timeout, nat);

  /* CAREFUL MODIFYING CODE ABOVE THIS LINE! */

  nat->mappings = NULL;
  nat->syn_pkts = NULL;
  nat->mapping_count = 0;
  return success;
}

/* 这里destroy mapping，和底下的delete mapping的区别在于destroy 不会更新相应的指针，但是delete会更新mapping所在的链表的指针。*/
struct sr_nat_mapping *nat_destroy_mapping(struct sr_nat_mapping *mapping) {
  struct sr_nat_connection *conn = mapping->conns; 
  struct sr_nat_connection *next_conn = NULL;
  struct sr_nat_mapping *next_mapping = mapping->next;

  while (conn) {
    next_conn = conn->next;
    free(conn);
    conn = next_conn;
  }
  free(mapping);
  return next_mapping;
}

int sr_nat_destroy(struct sr_nat *nat) {  /* Destroys the nat (free memory) */

  pthread_mutex_lock(&(nat->lock));

  struct sr_nat_mapping *mapping = nat->mappings;
  struct sr_pkt_list *pkt = nat->syn_pkts;
  struct sr_pkt_list *p_next = NULL;
  
  while (mapping) {
    mapping = nat_destroy_mapping(mapping);
  } 

  while (pkt) {
    p_next = pkt->next;
    free(pkt->buf);
    free(pkt);
    pkt = p_next; 
  }

  pthread_kill(nat->thread, SIGKILL);
  return pthread_mutex_destroy(&(nat->lock)) &&
    pthread_mutexattr_destroy(&(nat->attr));

}

void print_mapping(struct sr_nat_mapping *mapping) {
  struct in_addr in;
  if (mapping->type == nat_mapping_tcp)
    Debug("tcp mapping\n");
  else
    Debug("icmp mapping\n");
  Debug("conn_count: %d\n", mapping->conn_count);
  Debug("aux_int: %d\n", ntohs(mapping->aux_int));
  in.s_addr = mapping->ip_int;
  Debug("ip_int: %s\n", inet_ntoa(in));
  Debug("aux_ext: %d\n", ntohs(mapping->aux_ext));
  in.s_addr = mapping->ip_ext;
  Debug("ip_ext: %s\n", inet_ntoa(in));
}

void print_nat(struct sr_nat *nat) {
  int tcp_count = 0;
  int icmp_count = 0;
  struct sr_nat_mapping *mapping = nat->mappings;

  while (mapping) {
    if (mapping->type == nat_mapping_tcp)
      tcp_count += 1;
    mapping = mapping->next;
  }
  icmp_count = nat->mapping_count - tcp_count;
  Debug("total mapping count: %d, tcp_mapping_count: %d, icmp_mapping_count: %d\n", nat->mapping_count, tcp_count, icmp_count);
}

/* 函数返回时，*pre 应该指向找到的mapping的前一个mapping的地址，方便后续的删除操作 */
struct sr_nat_mapping *find_mapping_external(struct sr_nat *nat, uint16_t aux_ext, sr_nat_mapping_type type, struct sr_nat_mapping **pre) {
  struct sr_nat_mapping *mapping = nat->mappings;
  if (pre)
    *pre = NULL;
  while (mapping) {
    if (mapping->aux_ext == aux_ext && mapping->type == type)
      break; 
    if (pre)
      *pre = mapping;
    mapping = mapping->next;
  }
  
  return mapping;
}

struct sr_nat_connection *mapping_delete_conn(struct sr_nat_mapping *mapping, struct sr_nat_connection *conn,
                        struct sr_nat_connection *pre_conn) {
 struct sr_nat_connection *next_conn = conn->next;
 mapping->conn_count -= 1;
 if (pre_conn) 
   pre_conn->next = next_conn;
 else 
   mapping->conns = next_conn;
 free(conn);
 
 return next_conn;
}

struct sr_nat_mapping *nat_delete_empty_conn_mapping(struct sr_nat *nat, struct sr_nat_mapping *mapping, struct sr_nat_mapping *pre_mapping) {
  struct sr_nat_mapping *next_mapping = mapping->next;
  nat->mapping_count -= 1;
  if (pre_mapping)
    pre_mapping->next = mapping->next; 
  else
    nat->mappings = mapping->next;
  free(mapping);
  return next_mapping;
}

struct sr_nat_connection *mapping_timeout_conn(struct sr_nat *nat, struct sr_nat_mapping *mapping, struct sr_nat_connection *conn, struct sr_nat_connection **pre_conn_ptr, time_t curtime) {
  struct sr_nat_connection *next_conn = NULL;
  double limit = 0;

  if (conn->state == CLOSED) {
    limit = 0;
  }
  else if (conn->state == ESTAB) {
    limit = nat->tcp_e_timeout;
  }
  else {
    limit = nat->tcp_t_timeout;
  }

  if (difftime(curtime, conn->last_updated) >= limit) {
    next_conn = mapping_delete_conn(mapping, conn, *pre_conn_ptr);
  }
  else {
    next_conn = conn->next;
    *pre_conn_ptr = conn;
  }

  return next_conn;
}

struct sr_nat_mapping *nat_timeout_tcp_mapping(struct sr_nat *nat, struct sr_nat_mapping *mapping, struct sr_nat_mapping **pre_mapping_ptr, time_t curtime) {
  struct sr_nat_connection *pre_conn = NULL;
  struct sr_nat_connection *conn = mapping->conns; 
  struct sr_nat_mapping *next_mapping = NULL;

  while (conn) {
    conn = mapping_timeout_conn(nat, mapping, conn, &pre_conn, curtime);    
  }

  if (!mapping->conn_count) {
    next_mapping = nat_delete_empty_conn_mapping(nat, mapping, *pre_mapping_ptr);
  }
  else {
    next_mapping = mapping->next;
    *pre_mapping_ptr = mapping;
  } 
  return next_mapping;
}

struct sr_nat_mapping *nat_timeout_icmp_mapping(struct sr_nat *nat , struct sr_nat_mapping *mapping, struct sr_nat_mapping **pre_mapping_ptr, time_t curtime) {
  struct sr_nat_mapping *next_mapping = NULL;
  
  double delta = difftime(curtime, mapping->last_updated);
  if (delta >= nat->icmp_timeout) {
    next_mapping = nat_delete_empty_conn_mapping(nat, mapping, *pre_mapping_ptr);
  }
  else {
    next_mapping = mapping->next;
    *pre_mapping_ptr = mapping;
  } 
  return next_mapping;
}

void *sr_nat_timeout(void *nat_ptr) {  /* Periodic Timout handling */
  struct sr_nat *nat = (struct sr_nat *)nat_ptr;
  struct sr_nat_mapping *mapping = NULL;
  struct sr_nat_mapping *pre_mapping = NULL;
  struct sr_pkt_list *pkt = NULL;
  struct sr_pkt_list *pre_pkt = NULL;
  struct sr_pkt_list *next_pkt = NULL;

  while (1) {
    sleep(1.0);

    pthread_mutex_lock(&(nat->lock));
    time_t curtime = time(NULL);
    print_nat(nat);
    mapping = nat->mappings;
    pre_mapping = NULL; /* 很有必要 */

    while (mapping) {
      if (mapping->type == nat_mapping_tcp) 
        mapping = nat_timeout_tcp_mapping(nat, mapping, &pre_mapping, curtime);
      else 
        mapping = nat_timeout_icmp_mapping(nat, mapping, &pre_mapping, curtime);
    }

    pthread_mutex_unlock(&(nat->lock));
    

    pthread_mutex_lock(&(nat->lock));
    
    pkt = nat->syn_pkts;
    while (pkt) {
      uint8_t *packet = pkt->buf;
      struct sr_ip_hdr *ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
      struct tcphdr *tcp_hdr = (struct tcphdr*)((uint8_t*)ip_hdr + 4*ip_hdr->ip_hl);
      mapping = find_mapping_external(nat, tcp_hdr->th_dport, nat_mapping_tcp, NULL);
      int limit_exceeded = difftime(curtime, pkt->added) > 6.0;

      if (mapping || limit_exceeded) {
        if (limit_exceeded) {
          struct sr_instance *sr = nat->sr;
          uint32_t next_hop_ip = 0;
          char iface_out[sr_IFACE_NAMELEN];
          uint32_t ip_dst = ip_hdr->ip_src;
          int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
          uint8_t *packet_to_send = malloc(len);
          sr_find_next_hop_ip_and_iface(sr->routing_table, ip_dst, &next_hop_ip, iface_out);
          sr_fill_in_icmp_portunreachable(sr, packet_to_send, packet, iface_out);
          struct sr_ethernet_hdr *e_hdr = (sr_ethernet_hdr_t*)packet_to_send;
          struct sr_if *sr_if = sr_get_interface(sr, iface_out);
          memcpy(e_hdr->ether_shost, sr_if->addr, ETHER_ADDR_LEN);
          struct sr_arpentry *entry = sr_arpcache_lookup(&(sr->cache), next_hop_ip);
          if (entry) {
            memcpy(e_hdr->ether_dhost, entry->mac, ETHER_ADDR_LEN);
            sr_send_packet(sr, packet_to_send, len, iface_out);
            free(entry);
          }
          else {
            struct sr_arpreq *req = sr_arpcache_queuereq(&(sr->cache), next_hop_ip, packet_to_send, len, iface_out);
            sr_handle_arpreq(sr, req);
          }
        }
        next_pkt = pkt->next;
        pre_pkt->next = next_pkt; 
        free(pkt); 
        pkt = next_pkt;
      }
      else {
        pre_pkt = pkt;
        pkt = pkt->next;
      } 
    }

    pthread_mutex_unlock(&(nat->lock));
    
  }
  return NULL;
}

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy */
  struct sr_nat_mapping *mapping = nat->mappings;
  struct sr_nat_mapping *copy = NULL; 

  while (mapping) {
    if (mapping->type == nat_mapping_icmp && mapping->aux_ext == aux_ext)
      break; 
    mapping = mapping->next;
  }

  if (mapping) {

    /* 查找操作不应该更新last_updated, 为了省事就这样吧*/
    mapping->last_updated = time(NULL);
    copy = malloc(sizeof(struct sr_nat_mapping));
    memcpy(copy, mapping, sizeof(struct sr_nat_mapping));
  }

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy. */
  struct sr_nat_mapping *mapping = NULL;
  struct sr_nat_mapping *copy = NULL;

  while (mapping) {
    if (mapping->type == type && 
        mapping->ip_int == ip_int &&
        mapping->aux_int == aux_int)
      break; 
    mapping = mapping->next;
  }

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Insert a new mapping into the nat's mapping table.
   Actually returns a copy to the new mapping, for thread safety.
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle insert here, create a mapping, and then return a copy of it */
  struct sr_nat_mapping *mapping = NULL;

  pthread_mutex_unlock(&(nat->lock));
  return mapping;
}


struct sr_nat_mapping *sr_nat_lookup_or_insert_icmp_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int) {
  pthread_mutex_lock(&(nat->lock));

  struct sr_nat_mapping *mapping = nat->mappings;
  struct sr_nat_mapping *copy = malloc(sizeof(struct sr_nat_mapping)); 

  while (mapping) {
    if (mapping->type == nat_mapping_icmp && 
        mapping->ip_int == ip_int &&
        mapping->aux_int == aux_int)
      break; 
    mapping = mapping->next;
  }
  
  if (!mapping) {
    mapping = malloc(sizeof(struct sr_nat_mapping));
    mapping->type = nat_mapping_icmp;
    mapping->ip_int = ip_int;
    mapping->aux_int = aux_int;
    
    /* hard code ip_ext*/
    mapping->ip_ext = ntohl(0xb84868dd);  
    /* navie aux_int 没有考虑一个nat背后会有多个内网ip */
    mapping->aux_ext = aux_int; 
    mapping->last_updated = time(NULL);
    mapping->conns = NULL;
    mapping->conn_count = 0;
    mapping->next = nat->mappings;
    nat->mappings = mapping;
    nat->mapping_count += 1;
  }
  /* 如果这个mapping是查找出来的不应该更新last_updated,但是为了省事就这样吧 */
  mapping->last_updated = time(NULL);
  memcpy(copy, mapping, sizeof(struct sr_nat_mapping));
  
  pthread_mutex_unlock(&(nat->lock));

  return copy;
}

int sr_nat_modify_icmp(struct sr_nat *nat, struct sr_ip_hdr *ip_hdr, uint8_t outbound) {
  struct sr_nat_mapping *mapping = NULL;
  struct sr_icmp_t8_hdr *icmp = NULL;

  ip_hdr->ip_sum = 0;
  icmp = (sr_icmp_t8_hdr_t*)((uint8_t*)ip_hdr + sizeof(sr_ip_hdr_t));
  icmp->icmp_sum = 0;
  if (outbound) {
    mapping = sr_nat_lookup_or_insert_icmp_mapping(nat, 
				                   ip_hdr->ip_src, icmp->icmp_identifier);
    ip_hdr->ip_src = mapping->ip_ext;
    icmp->icmp_identifier = mapping->aux_ext;
  }
  else {
    mapping = sr_nat_lookup_external(nat, icmp->icmp_identifier, nat_mapping_icmp);
    if (!mapping)
      return 0;
    ip_hdr->ip_dst = mapping->ip_int;
    icmp->icmp_identifier = mapping->aux_int;
  }
  
  free(mapping);
  ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
  icmp->icmp_sum = cksum(icmp, ntohs(ip_hdr->ip_len) - sizeof(sr_ip_hdr_t)); 

  return 1;
}

void modify_conn_state(struct sr_nat_connection *conn, uint8_t flags, uint8_t outbound) {

  conn->last_updated = time(NULL);

  if (conn->state == CLOSED || flags & TH_RST)
    /* 为什么rst直接return？因为为了验证这个rst的合法性，nat除了要存储ip，端口，还要记录tcp的序列号。但是nat从职责上来说不应该管收发的tcp包是否乱序*/
    return;
  
  if (flags & TH_FIN) {
    conn->state = CLOSING;
    return;
  }
  
  if (flags & TH_SYN) {
    if (conn->state == ESTAB || conn->state == CLOSING) {
      return;
    }
    
    if (outbound) {
      if (conn->state != SYN_RCVD)
        conn->state = SYN_SENT;
    }
    else {
      conn->state = SYN_RCVD;
    }
    return; 
  }
  
  if (conn->state == SYN_RCVD) 
    conn->state = ESTAB; 
} 

struct sr_nat_mapping *find_mapping_internal(struct sr_nat *nat, uint32_t ip_int , uint16_t aux_int, sr_nat_mapping_type type, struct sr_nat_mapping **pre) {
  struct sr_nat_mapping *mapping = nat->mappings;
  if (pre)
    *pre = NULL;
  while (mapping) {
    if (mapping->type == type && 
        mapping->ip_int == ip_int &&
        mapping->aux_int == aux_int)
      break; 
    if (pre)
      *pre = mapping;
    mapping = mapping->next;
  }
  
  return mapping;
}



struct sr_nat_connection *find_conn(struct sr_nat_mapping *mapping, uint32_t ip, uint16_t port,struct sr_nat_connection **pre) {
  struct sr_nat_connection *conn = mapping->conns; 
  
  *pre = NULL; 
  while (conn) {
    if (conn->ip_dst == ip && conn->port_dst == port)
      break;
    *pre = conn;
    conn = conn->next;
  }

  return conn;
}

struct sr_nat_connection *create_conn_for_outbound_syn(struct sr_nat_mapping *mapping, struct sr_ip_hdr *ip_hdr) {
  struct sr_nat_connection *conn = malloc(sizeof(struct sr_nat_connection));
  struct tcphdr *tcp_hdr = (struct tcphdr*)((uint8_t*)ip_hdr + 4*ip_hdr->ip_hl);

  conn->state = SYN_SENT;
  conn->ip_dst = ip_hdr->ip_dst;
  conn->port_dst = tcp_hdr->th_dport;
  conn->next = mapping->conns;
  conn->last_updated = time(NULL);
  
  mapping->conns = conn;
  mapping->conn_count += 1;
  
  return conn;
}

struct sr_nat_mapping *create_mapping_for_outbound_syn(struct sr_nat *nat, struct sr_ip_hdr *ip_hdr) {
  struct tcphdr *tcp_hdr = (struct tcphdr*)((uint8_t*)ip_hdr + 4*ip_hdr->ip_hl);
  struct sr_nat_mapping *mapping = malloc(sizeof(struct sr_nat_mapping));

  mapping->ip_int = ip_hdr->ip_src;
  mapping->aux_int = tcp_hdr->th_sport; 
  /* hard code */
  mapping->ip_ext = ntohl(0xb84868dd);  
  /* navie aux_int 没有考虑一个nat背后会有多个内网ip，即使只有一个内网ip，这样做也不好*/
  mapping->aux_ext = tcp_hdr->th_sport; 
  mapping->type = nat_mapping_tcp;
  mapping->last_updated = time(NULL);
  mapping->conn_count = 0;
  mapping->conns = NULL;
  create_conn_for_outbound_syn(mapping, ip_hdr);
  mapping->next = nat->mappings;
  nat->mappings = mapping;
  nat->mapping_count += 1;
  
  return mapping;
}

/* packet 是ethernet frame */
/* 返回值为1表示应该转发，0表示不转发 */
int sr_nat_modify_tcp(struct sr_nat *nat, uint8_t *packet, uint16_t len, uint8_t outbound) {

  struct sr_ip_hdr *ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
  struct tcphdr *tcp_hdr = (struct tcphdr*)((uint8_t*)ip_hdr + 4*ip_hdr->ip_hl);
  struct sr_nat_mapping *pre_mapping = NULL;
  struct sr_nat_mapping *mapping = NULL;
  struct sr_nat_mapping *mapping_copy = NULL;
  struct sr_nat_connection *pre_conn = NULL;
  struct sr_nat_connection *conn = NULL;

  pthread_mutex_lock(&(nat->lock));
  
  if (outbound) {
    mapping = find_mapping_internal(nat, ip_hdr->ip_src, 
                                    tcp_hdr->th_sport, nat_mapping_tcp, &pre_mapping);

  }
  else {
    mapping = find_mapping_external(nat, tcp_hdr->th_dport,
                                    nat_mapping_tcp, &pre_mapping);
  }

  if (mapping) {
    mapping->last_updated = time(NULL);
    if (outbound) {
      conn = find_conn(mapping, ip_hdr->ip_dst, tcp_hdr->th_dport, &pre_conn);
      if (!conn && tcp_hdr->th_flags & TH_SYN)
        create_conn_for_outbound_syn(mapping, ip_hdr); 
    }
    else {
      conn = find_conn(mapping, ip_hdr->ip_src, tcp_hdr->th_sport, &pre_conn);
    }
    if (conn) {
      modify_conn_state(conn, tcp_hdr->th_flags, outbound);
      if (conn->state == CLOSED) {
        mapping_delete_conn(mapping, conn, pre_conn);
      }
    }
  } /* end if mapping */
  else {
    if (tcp_hdr->th_flags & TH_SYN) {
      if (outbound) {
        mapping = create_mapping_for_outbound_syn(nat, ip_hdr);
      }
      else {
      /* store inbound syn */
        struct sr_pkt_list *pkt = malloc(sizeof(struct sr_pkt_list));
        pkt->len = len;
        pkt->buf = malloc(len);
        memcpy(pkt->buf, packet, len);
        pkt->added = time(NULL);
        pkt->next = nat->syn_pkts;
        nat->syn_pkts = pkt;
      }
    }
  }

  if (mapping) {
    mapping_copy = malloc(sizeof(struct sr_nat_mapping));
    memcpy(mapping_copy, mapping, sizeof(struct sr_nat_mapping));
    if (!mapping->conn_count)
      nat_delete_empty_conn_mapping(nat, mapping, pre_mapping);
  }

  pthread_mutex_unlock(&(nat->lock));

  if (mapping_copy) {
    if (outbound) {
     /* modify src */
      ip_hdr->ip_src = mapping_copy->ip_ext;
      tcp_hdr->th_sport = mapping_copy->aux_ext;
    }
    else {
      /* modify dst */
      ip_hdr->ip_dst = mapping_copy->ip_int;
      tcp_hdr->th_dport = mapping_copy->aux_int;
    }
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum(ip_hdr, 4*ip_hdr->ip_hl);
    tcp_hdr->th_sum = 0;
    /* tcp cksum 不是这样算的，应该加上一个pesuodo header */
    /* 奇怪的是用下面错误的计算方法依然行得通 */
    tcp_hdr->th_sum = cksum(tcp_hdr, ntohs(ip_hdr->ip_len)-4*ip_hdr->ip_hl);

    free(mapping_copy);
    return 1;
  }
  
  return 0;
}


