/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_nat.h"
#include "sr_utils.h"
#include "sr_icmp.h"


int is_corrupt(struct sr_ip_hdr *packet);


int sr_prepare_forward_packet(struct sr_instance *sr, uint8_t *packet, uint8_t **packet_to_send, uint32_t *next_hop_ip, char *ifaceout); 

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */
    if (sr->nat_on) {
      sr_nat_init(&(sr->nat));
      sr->nat.sr = sr;
    }

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  struct sr_ethernet_hdr* e_hdr = 0;
  struct sr_arp_hdr* a_hdr = 0;
  struct sr_ip_hdr* ip_hdr = 0; 
  struct sr_icmp_hdr* icmp_hdr = 0;
  struct sr_if *sr_if = 0;
  int dst_is_router = 0;
  uint32_t next_hop_ip = 0;
  struct sr_arpentry *entry = 0;
  uint32_t ip_dst = 0;
  uint8_t* packet_to_send = packet;
  uint8_t should_free = 0;   /* should free packet_to_send */
  char iface_out[sr_IFACE_NAMELEN];
  struct sr_arpreq *req = 0;
  uint8_t internal = 0;       /* 只有开启nat时才有意义表示interface是内部还是外部接口 */
  uint8_t ip_dst_public = 0; /* 只有开启nat时才有意义表明终点ip是否是公网地址 */

  /* 先判断是否是arp请求 */
  e_hdr = (struct sr_ethernet_hdr*) packet;
  /* ARP */
  if (e_hdr->ether_type == htons(ethertype_arp)) {
    a_hdr = (struct sr_arp_hdr*)(packet + sizeof(struct sr_ethernet_hdr));
    if (a_hdr->ar_op == htons(arp_op_reply)) {
      sr_handle_arp_reply(sr, a_hdr); 
    }
    else {
      sr_response_arp_req(sr, a_hdr, interface);
    }

    return;
  }  
  
  /* 针对ip packet一些基本的过滤 */
  if(e_hdr->ether_type != htons(ethertype_ip))
    return;

  ip_hdr = (struct sr_ip_hdr*)(packet + sizeof(struct sr_ethernet_hdr));
  if (is_corrupt(ip_hdr))
    return;

  if (ip_hdr->ip_ttl <= 0)
    return;

  if (ip_hdr->ip_p != ip_protocol_icmp && ip_hdr->ip_p != ip_protocol_tcp && ip_hdr->ip_p != ip_protocol_udp)
    return;
 
  /* 这里的nat就不处理udp了省事 */
  if (sr->nat_on) {
    /* hard code 因为nat模式一共就两个接口 1为内部接口，2为外部 */
    /* 当然日常用的nat是可能有多个接口*/
    internal = strcmp(interface, "eth1") == 0;
    /* hard code */
    ip_dst_public = 1;
    if (ip_hdr->ip_p == ip_protocol_udp)
      return;
  }

  /* icmp且终点为路由器接口时，只有两种情况路由器会有反应*/
  /* 第一种echo request 第二种nat开启时inbound echo reply */
  dst_is_router = sr_is_ip_in_if_list(sr, ip_hdr->ip_dst);
  if (ip_hdr->ip_p == ip_protocol_icmp) {
    icmp_hdr = (struct sr_icmp_hdr*)((uint8_t*)ip_hdr + sizeof(struct sr_ip_hdr));
    if (icmp_hdr->icmp_type != 8) 
      if (dst_is_router) {
        if (!(sr->nat_on && !internal && icmp_hdr->icmp_type==0))
          return;
      }
  }
  

  if (dst_is_router) {
    if (ip_hdr->ip_p == ip_protocol_icmp) {
       /* ICMP */
       if (icmp_hdr->icmp_type == 8) {
         icmp_hdr = (struct sr_icmp_hdr*)((uint8_t*)ip_hdr + sizeof(struct sr_ip_hdr));
         ip_dst = ip_hdr->ip_src;
         should_free = 1;
         len = sizeof(sr_ethernet_hdr_t) + ntohs(ip_hdr->ip_len);
         packet_to_send = malloc(len);
         sr_find_next_hop_ip_and_iface(sr->routing_table, ip_dst, &next_hop_ip, iface_out);
         sr_fill_in_icmp_reply(sr, packet_to_send, packet, iface_out);
       }
       else {
        /* inbound translate */
         if (!sr_nat_modify_icmp(&(sr->nat), ip_hdr, INBOUND))
           return;
         should_free = !sr_prepare_forward_packet(sr, packet, &packet_to_send, &next_hop_ip, iface_out);
       }
    } 
    else {
       /* TCP UDP */
      if (!sr->nat_on || internal) {
        ip_dst = ip_hdr->ip_src;
        should_free = 1;
        len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t); 
        packet_to_send = malloc(len);
        sr_find_next_hop_ip_and_iface(sr->routing_table, ip_dst, &next_hop_ip, iface_out);
        sr_fill_in_icmp_portunreachable(sr, packet_to_send, packet, iface_out);
      }
      else {
       /* tcp inbound translate */ 
        if (!sr_nat_modify_tcp(&(sr->nat), packet, len, INBOUND))
          return;
         should_free = !sr_prepare_forward_packet(sr, packet, &packet_to_send, &next_hop_ip, iface_out);
      }
    }
  } /* end if dst_is_router */
    
  /* 目标ip不是路由器接口可能需要转发ip packet */ 
  else {
    int result;
    result = sr_prepare_forward_packet(sr, packet, &packet_to_send, &next_hop_ip, iface_out);
    should_free = !result;
    if (result && sr->nat_on && ip_dst_public) {
      /* 如果目标ip地址是内网地址，nat什么都不需要做 */
      if (ip_hdr->ip_p == ip_protocol_icmp) {
        sr_nat_modify_icmp(&(sr->nat), ip_hdr, OUTBOUND);
      }
      else {
        sr_nat_modify_tcp(&(sr->nat), packet, len, OUTBOUND);
      }
    } 
  } /* end 可能需要转发 */
    
  e_hdr = (sr_ethernet_hdr_t*)packet_to_send;
  sr_if = sr_get_interface(sr, iface_out);
  memcpy(e_hdr->ether_shost, sr_if->addr, ETHER_ADDR_LEN); 
  entry = sr_arpcache_lookup(&(sr->cache), next_hop_ip);
  if (entry) {
    memcpy(e_hdr->ether_dhost, entry->mac, ETHER_ADDR_LEN); 
    sr_send_packet(sr, packet_to_send, len, iface_out);
    free(entry);
  }
  else {
    req = sr_arpcache_queuereq(&(sr->cache), next_hop_ip, packet_to_send, len, iface_out);
    sr_handle_arpreq(sr, req); 
  }
  
  if (should_free) 
    free(packet_to_send);
}/* end sr_ForwardPacket */

int is_corrupt(struct sr_ip_hdr *packet) {
  uint16_t sum1 = packet->ip_sum;
  uint16_t sum2;

  packet->ip_sum = 0;
  sum2 = cksum(packet, 4*packet->ip_hl);
  packet->ip_sum = sum1;
  return sum1 != sum2;
}

void decrement_ttl(struct sr_ip_hdr *ip_hdr) {
  ip_hdr->ip_ttl -= 1;
  ip_hdr->ip_sum = 0;
  ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
}

/* 对可能需要转发的pkt进行一些处理
   减ttl如果ttl变为0，生成相应的icmp消息。如果找不到下一跳ip地址，也需要生成相应的icmp消息
   返回值表示该pkt是否可以转发
   *packet_to_send 应指向路由器需要发送的packet
*/ 
int sr_prepare_forward_packet(struct sr_instance *sr, uint8_t *packet, uint8_t **packet_to_send, uint32_t *next_hop_ip, char *iface_out) {

  int forward = 0;
  uint32_t ip_dst = 0;
  unsigned int len = 0;
  struct sr_ip_hdr *ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));

  if (ip_hdr->ip_ttl - 1 <= 0) {
    ip_dst = ip_hdr->ip_src;
    len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t11_hdr_t); 
    forward = 0;
    *packet_to_send = malloc(len);
    sr_find_next_hop_ip_and_iface(sr->routing_table, ip_dst, next_hop_ip, iface_out);
    sr_fill_in_icmp_time_exceeded(sr, *packet_to_send, packet, iface_out);
  }
  else {
    decrement_ttl(ip_hdr);
    ip_dst = ip_hdr->ip_dst;
    if (!sr_find_next_hop_ip_and_iface(sr->routing_table, ip_dst, next_hop_ip, iface_out)) {
      ip_dst = ip_hdr->ip_src;
      forward = 0;
      len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t); 
      *packet_to_send = malloc(len);
      sr_find_next_hop_ip_and_iface(sr->routing_table, ip_dst, next_hop_ip, iface_out);
      sr_fill_in_icmp_netunreachable(sr, *packet_to_send, packet, iface_out);
    }
    else {
      forward = 1;
      *packet_to_send = packet;
    }
  }
  return forward;
}


