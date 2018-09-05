#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sr_utils.h"
#include "sr_icmp.h"

void sr_icmp_config_ethernet_ip_headers(struct sr_instance *sr, uint8_t* packet, uint8_t* in_packet, unsigned int ip_len, const char *iface, int use_iface_ip) {
  struct sr_ethernet_hdr *e_hdr = 0;
  struct sr_ethernet_hdr *in_e_hdr = 0;
  struct sr_ip_hdr *ip_hdr = 0;
  struct sr_ip_hdr *in_ip_hdr = 0;
  struct sr_if *sr_if = 0;

  sr_if = sr_get_interface(sr, iface);
  
  e_hdr = (sr_ethernet_hdr_t*)packet;
  in_e_hdr = (sr_ethernet_hdr_t*)in_packet; 
  e_hdr->ether_type = in_e_hdr->ether_type;
  memcpy(e_hdr->ether_shost, sr_if->addr, ETHER_ADDR_LEN);  

  ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
  in_ip_hdr = (sr_ip_hdr_t*)(in_packet + sizeof(sr_ethernet_hdr_t));
  ip_hdr->ip_hl = in_ip_hdr->ip_hl;
  ip_hdr->ip_v = in_ip_hdr->ip_v;
  ip_hdr->ip_tos = in_ip_hdr->ip_tos;
  ip_hdr->ip_len = htons(ip_len);
  ip_hdr->ip_id = 0;
  ip_hdr->ip_off = 0;
  ip_hdr->ip_ttl = 64;
  ip_hdr->ip_p = ip_protocol_icmp;
  ip_hdr->ip_src = use_iface_ip ? sr_if->ip : in_ip_hdr->ip_dst;
  ip_hdr->ip_dst = in_ip_hdr->ip_src;
  ip_hdr->ip_sum = 0;
  ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
}

void sr_fill_in_icmp_t3(struct sr_instance *sr, uint8_t code, uint8_t *packet_to_send, uint8_t *packet, const char* iface, int use_iface_ip) {
  struct sr_icmp_t3_hdr *icmp_hdr = 0;
  struct sr_ip_hdr *ip_hdr = 0; 

  sr_icmp_config_ethernet_ip_headers(sr, packet_to_send, packet, sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t3_hdr_t), iface, use_iface_ip);  
  icmp_hdr = (sr_icmp_t3_hdr_t*)(packet_to_send + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  icmp_hdr->icmp_type = 3;
  icmp_hdr->icmp_code = code;
  icmp_hdr->next_mtu = 0;
  icmp_hdr->icmp_sum = 0;
  icmp_hdr->unused = 0; 
  
  ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
  memcpy((uint8_t*)icmp_hdr + 8, ip_hdr, sizeof(sr_ip_hdr_t)+8);
  icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_t3_hdr_t)); 
}

void sr_fill_in_icmp_reply(struct sr_instance *sr, uint8_t *packet_to_send, uint8_t *echo_packet, const char *iface) {
  struct sr_icmp_t0_hdr *reply_icmp_hdr = 0;
  struct sr_icmp_t8_hdr *echo_hdr = 0;
  struct sr_ip_hdr *echo_ip_hdr = 0; 
  struct sr_ip_hdr *ip_hdr_to_send = 0;
  unsigned int data_len = 0;
 
  reply_icmp_hdr = (sr_icmp_t0_hdr_t*)(packet_to_send + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  echo_hdr = (sr_icmp_t8_hdr_t*)(echo_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  echo_ip_hdr = (sr_ip_hdr_t*)(echo_packet + sizeof(sr_ethernet_hdr_t)); 

  sr_icmp_config_ethernet_ip_headers(sr, packet_to_send, echo_packet, ntohs(echo_ip_hdr->ip_len), iface, 0);

  ip_hdr_to_send = (sr_ip_hdr_t*)(packet_to_send + sizeof(sr_ethernet_hdr_t));
  ip_hdr_to_send->ip_src = echo_ip_hdr->ip_dst;
  ip_hdr_to_send->ip_sum = 0;
  ip_hdr_to_send->ip_sum = cksum(ip_hdr_to_send, sizeof(sr_ip_hdr_t));
  reply_icmp_hdr->icmp_type = 0;
  reply_icmp_hdr->icmp_code = 0;
  reply_icmp_hdr->icmp_identifier = echo_hdr->icmp_identifier;
  reply_icmp_hdr->icmp_seq = echo_hdr->icmp_seq;
  reply_icmp_hdr->icmp_sum = 0; 
  
  data_len = ntohs(echo_ip_hdr->ip_len) - 
		                 sizeof(sr_ip_hdr_t) - 
				 sizeof(sr_icmp_t8_hdr_t);
  memcpy((uint8_t*)reply_icmp_hdr + sizeof(sr_icmp_t0_hdr_t), (uint8_t*)echo_hdr + sizeof(sr_icmp_t8_hdr_t), data_len);
  reply_icmp_hdr->icmp_sum = cksum(reply_icmp_hdr, sizeof(sr_icmp_t0_hdr_t) + data_len);
}

void sr_fill_in_icmp_netunreachable(struct sr_instance *sr, uint8_t *packet_to_send, uint8_t *packet, const char *iface) {
  sr_fill_in_icmp_t3(sr, 0, packet_to_send, packet, iface, 1);
}

void sr_fill_in_icmp_hostunreachable(struct sr_instance *sr, uint8_t *packet_to_send, uint8_t *packet, const char *iface) {
  sr_fill_in_icmp_t3(sr, 1, packet_to_send, packet, iface, 1);
}

void sr_fill_in_icmp_portunreachable(struct sr_instance *sr, uint8_t *packet_to_send, uint8_t *packet, const char *iface) {
  sr_fill_in_icmp_t3(sr, 3, packet_to_send, packet, iface, 0);
}


void sr_fill_in_icmp_time_exceeded(struct sr_instance *sr, uint8_t *packet_to_send, uint8_t *packet, const char *iface) {
  struct sr_icmp_t11_hdr *icmp_hdr = 0;
  struct sr_ip_hdr *ip_hdr = 0; 

  sr_icmp_config_ethernet_ip_headers(sr, packet_to_send, packet, sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t11_hdr_t), iface, 1);  
  icmp_hdr = (sr_icmp_t11_hdr_t*)(packet_to_send + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  icmp_hdr->icmp_type = 11;
  icmp_hdr->icmp_code = 0;
  icmp_hdr->icmp_sum = 0;
  icmp_hdr->unused = 0; 
  
  ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
  memcpy((uint8_t*)icmp_hdr + 8, ip_hdr, sizeof(sr_ip_hdr_t)+8);
  icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_t11_hdr_t)); 
}
