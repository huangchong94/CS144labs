#ifndef SR_ICMP_H
#define SR_ICMP_H

#include "sr_router.h"

void sr_fill_in_icmp_reply(struct sr_instance *sr, uint8_t *packet_to_send, uint8_t *echo_packet, const char* iface);

void sr_fill_in_icmp_netunreachable(struct sr_instance *sr, uint8_t *packet_to_send, uint8_t *packet, const char *iface);

void sr_fill_in_icmp_hostunreachable(struct sr_instance *sr, uint8_t *packet_to_send, uint8_t *packet, const char *iface); 

void sr_fill_in_icmp_portunreachable(struct sr_instance *sr, uint8_t *packet_to_send, uint8_t *packet, const char *iface); 

void sr_fill_in_icmp_time_exceeded(struct sr_instance *sr, uint8_t *packet_to_send, uint8_t *packet, const char *iface);

#endif
