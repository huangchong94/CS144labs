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
#include "sr_utils.h"
#include "sr_icmp.h"


int is_corrupt(struct sr_ip_hdr *packet);

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
  uint32_t next_hop_ip = 0;
  struct sr_arpentry *entry = 0;
  uint32_t ip_dst = 0;
  uint8_t* packet_to_send = 0;
  uint8_t forward_packet = 0;
  char iface_out[sr_IFACE_NAMELEN];
  struct sr_arpreq *req = 0;

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
  }  
  
  /* IP */
  else if(e_hdr->ether_type == htons(ethertype_ip)) {
    ip_hdr = (struct sr_ip_hdr*)(packet + sizeof(struct sr_ethernet_hdr));

    /* checksum */
    if (is_corrupt(ip_hdr))
      return;
    if (ip_hdr->ip_ttl <= 0)
      return;
    
    /* 判断终点ip是否是路由器的接口ip */
    if (sr_is_ip_in_if_list(sr, ip_hdr->ip_dst)) {
      if (ip_hdr->ip_p == ip_protocol_icmp) {
         /* ICMP */
         icmp_hdr = (struct sr_icmp_hdr*)((uint8_t*)ip_hdr + sizeof(struct sr_ip_hdr));
	 if (icmp_hdr->icmp_type == 8) {
            forward_packet = 0;
            ip_dst = ip_hdr->ip_src;
            len = sizeof(sr_ethernet_hdr_t) + ntohs(ip_hdr->ip_len);
            packet_to_send = malloc(len);
            sr_find_next_hop_ip_and_iface(sr->routing_table, ip_dst, &next_hop_ip, iface_out);
            sr_fill_in_icmp_reply(sr, packet_to_send, packet, iface_out);
         }
         else {
           return;
         }
      } 
      else if (ip_hdr->ip_p == ip_protocol_tcp || ip_hdr->ip_p == ip_protocol_udp){
       /* TCP UDP */
        forward_packet = 0;
        ip_dst = ip_hdr->ip_src;
        len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t); 
        packet_to_send = malloc(len);
        sr_find_next_hop_ip_and_iface(sr->routing_table, ip_dst, &next_hop_ip, iface_out);
        sr_fill_in_icmp_portunreachable(sr, packet_to_send, packet, iface_out);
      }
      else {
        return;
      }
    }
    
    /* 可能需要转发ip packet */ 
    else {
	if (ip_hdr->ip_ttl - 1 <= 0) {
          forward_packet = 0;
          ip_dst = ip_hdr->ip_src;
          len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t11_hdr_t); 
          packet_to_send = malloc(len);
          sr_find_next_hop_ip_and_iface(sr->routing_table, ip_dst, &next_hop_ip, iface_out);
          sr_fill_in_icmp_time_exceeded(sr, packet_to_send, packet, iface_out);
        }
        else {
          ip_hdr->ip_ttl -= 1;
          ip_hdr->ip_sum = 0;
          ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
          packet_to_send = packet;
          ip_dst = ip_hdr->ip_dst;
          if (!sr_find_next_hop_ip_and_iface(sr->routing_table, ip_dst, &next_hop_ip, iface_out)) {
            forward_packet = 0;
            ip_dst = ip_hdr->ip_src;
            len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t); 
            packet_to_send = malloc(len);
            sr_find_next_hop_ip_and_iface(sr->routing_table, ip_dst, &next_hop_ip, iface_out);
            sr_fill_in_icmp_netunreachable(sr, packet_to_send, packet, iface_out);
          }
         else { 
           forward_packet = 1;
           sr_if = sr_get_interface(sr, iface_out);
           memcpy(e_hdr->ether_shost, sr_if->addr, ETHER_ADDR_LEN); 
         }
       }
    }
    
    e_hdr = (sr_ethernet_hdr_t*)packet_to_send;
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
    if (!forward_packet)
      free(packet_to_send);
  }
}/* end sr_ForwardPacket */

int is_corrupt(struct sr_ip_hdr *packet) {
  uint16_t sum1 = packet->ip_sum;
  uint16_t sum2;

  packet->ip_sum = 0;
  sum2 = cksum(packet, 4*packet->ip_hl);
  packet->ip_sum = sum1;
  return sum1 != sum2;
}

