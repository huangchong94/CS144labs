#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_rt.h"
#include "sr_icmp.h"

/* 
  This function gets called every second. For each request sent out, we keep
  checking whether we should resend an request or destroy the arp request.
  See the comments in the header file for an idea of what it should look like.
*/
void sr_arpcache_sweepreqs(struct sr_instance *sr) { 
  struct sr_arpreq *req = sr->cache.requests;
  struct sr_arpreq *next = 0; 
  while (req) {
    next = req->next;
    sr_handle_arpreq(sr, req);
    req = next;
  }
}

/* You should not need to touch the rest of this code. */

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
   You must free the returned structure if it is not NULL. */
struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip) {
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpentry *entry = NULL, *copy = NULL;
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if ((cache->entries[i].valid) && (cache->entries[i].ip == ip)) {
            entry = &(cache->entries[i]);
        }
    }
    
    /* Must return a copy b/c another thread could jump in and modify
       table after we return. */
    if (entry) {
        copy = (struct sr_arpentry *) malloc(sizeof(struct sr_arpentry));
        memcpy(copy, entry, sizeof(struct sr_arpentry));
    }
        
    pthread_mutex_unlock(&(cache->lock));
    
    return copy;
}

/* Adds an ARP request to the ARP request queue. If the request is already on
   the queue, adds the packet to the linked list of packets for this sr_arpreq
   that corresponds to this ARP request. You should free the passed *packet.
   
   A pointer to the ARP request is returned; it should not be freed. The caller
   can remove the ARP request from the queue by calling sr_arpreq_destroy. */
struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache,
                                       uint32_t ip,
                                       uint8_t *packet,           /* borrowed */
                                       unsigned int packet_len,
                                       char *iface)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            break;
        }
    }
    
    /* If the IP wasn't found, add it */
    if (!req) {
        req = (struct sr_arpreq *) calloc(1, sizeof(struct sr_arpreq));
        req->ip = ip;
        req->next = cache->requests;
        cache->requests = req;
    }
    
    /* Add the packet to the list of packets for this request */
    if (packet && packet_len && iface) {
        struct sr_packet *new_pkt = (struct sr_packet *)malloc(sizeof(struct sr_packet));
        
        new_pkt->buf = (uint8_t *)malloc(packet_len);
        memcpy(new_pkt->buf, packet, packet_len);
        new_pkt->len = packet_len;
		new_pkt->iface = (char *)malloc(sr_IFACE_NAMELEN);
        strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);
        new_pkt->next = req->packets;
        req->packets = new_pkt;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* 无锁版arpcache_insert */
struct sr_arpreq *arpcache_insert(struct sr_arpcache *cache,
                                     unsigned char *mac,
                                     uint32_t ip) {
    struct sr_arpreq *req, *prev = NULL, *next = NULL; 
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {            
            if (prev) {
                next = req->next;
                prev->next = next;
            } 
            else {
                next = req->next;
                cache->requests = next;
            }
            
            break;
        }
        prev = req;
    }
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if (!(cache->entries[i].valid))
            break;
    }
    
    if (i != SR_ARPCACHE_SZ) {
        memcpy(cache->entries[i].mac, mac, 6);
        cache->entries[i].ip = ip;
        cache->entries[i].added = time(NULL);
        cache->entries[i].valid = 1;
    }
    return req;
}

/* This method performs two functions:
   1) Looks up this IP in the request queue. If it is found, returns a pointer
      to the sr_arpreq with this IP. Otherwise, returns NULL.
   2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
                                     unsigned char *mac,
                                     uint32_t ip)
{
    struct sr_arpreq *req = NULL;
    pthread_mutex_lock(&(cache->lock));
    req = arpcache_insert(cache, mac, ip); 
    pthread_mutex_unlock(&(cache->lock));
    return req;
}

/* 无锁版arpreq_destroy */
void arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry) {
    if (entry) {
        struct sr_arpreq *req, *prev = NULL, *next = NULL; 
        for (req = cache->requests; req != NULL; req = req->next) {
            if (req == entry) {                
                if (prev) {
                    next = req->next;
                    prev->next = next;
                } 
                else {
                    next = req->next;
                    cache->requests = next;
                }
                
                break;
            }
            prev = req;
        }
        
        struct sr_packet *pkt, *nxt;
        
        for (pkt = entry->packets; pkt; pkt = nxt) {
            nxt = pkt->next;
            if (pkt->buf)
                free(pkt->buf);
            if (pkt->iface)
                free(pkt->iface);
            free(pkt);
        }
        
        free(entry);
    }
}
/* Frees all memory associated with this arp request entry. If this arp request
   entry is on the arp request queue, it is removed from the queue. */
void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry) {
    pthread_mutex_lock(&(cache->lock));
    arpreq_destroy(cache, entry); 
    pthread_mutex_unlock(&(cache->lock));
}

/* Prints out the ARP table. */
void sr_arpcache_dump(struct sr_arpcache *cache) {
    fprintf(stderr, "\nMAC            IP         ADDED                      VALID\n");
    fprintf(stderr, "-----------------------------------------------------------\n");
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        struct sr_arpentry *cur = &(cache->entries[i]);
        unsigned char *mac = cur->mac;
        fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(cur->ip), ctime(&(cur->added)), cur->valid);
    }
    
    fprintf(stderr, "\n");
}

/* Initialize table + table lock. Returns 0 on success. */
int sr_arpcache_init(struct sr_arpcache *cache) {  
    /* Seed RNG to kick out a random entry if all entries full. */
    srand(time(NULL));
    
    /* Invalidate all entries */
    memset(cache->entries, 0, sizeof(cache->entries));
    cache->requests = NULL;
    
    /* Acquire mutex lock */
    pthread_mutexattr_init(&(cache->attr));
    pthread_mutexattr_settype(&(cache->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(cache->lock), &(cache->attr));
    
    return success;
}

/* Destroys table + table lock. Returns 0 on success. */
int sr_arpcache_destroy(struct sr_arpcache *cache) {
    return pthread_mutex_destroy(&(cache->lock)) && pthread_mutexattr_destroy(&(cache->attr));
}

/* Thread which sweeps through the cache and invalidates entries that were added
   more than SR_ARPCACHE_TO seconds ago. */
void *sr_arpcache_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
    struct sr_arpcache *cache = &(sr->cache);
    
    while (1) {
        sleep(1.0);
        
        pthread_mutex_lock(&(cache->lock));
    
        time_t curtime = time(NULL);
        
        int i;    
        for (i = 0; i < SR_ARPCACHE_SZ; i++) {
            if ((cache->entries[i].valid) && (difftime(curtime,cache->entries[i].added) > SR_ARPCACHE_TO)) {
                cache->entries[i].valid = 0;
            }
        }
        
        sr_arpcache_sweepreqs(sr);

        pthread_mutex_unlock(&(cache->lock));
    }
    
    return NULL;
}

int sr_response_arp_req(struct sr_instance *sr, struct sr_arp_hdr *arp_hdr, char *interface) {
  struct sr_if *sr_if = sr_get_interface(sr, interface);
  struct sr_ethernet_hdr *resp;
  struct sr_arp_hdr *resp_arp_hdr;
  unsigned int len;
  int result;
  if (!sr_if)
    return 1;
 
  len = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr); 
  resp = (struct sr_ethernet_hdr*)malloc(len); 
  memcpy(resp->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
  memcpy(resp->ether_shost, sr_if->addr, ETHER_ADDR_LEN);
  resp->ether_type = htons(ethertype_arp);
  
  resp_arp_hdr = (struct sr_arp_hdr*)((uint8_t*)resp + sizeof(struct sr_ethernet_hdr));
  resp_arp_hdr->ar_hrd = arp_hdr->ar_hrd;
  resp_arp_hdr->ar_pro = arp_hdr->ar_pro;
  resp_arp_hdr->ar_hln = arp_hdr->ar_hln;
  resp_arp_hdr->ar_pln = arp_hdr->ar_pln; 
  resp_arp_hdr->ar_op = htons(arp_op_reply); 
  memcpy(resp_arp_hdr->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
  memcpy(resp_arp_hdr->ar_sha, sr_if->addr, ETHER_ADDR_LEN);
  resp_arp_hdr->ar_tip = arp_hdr->ar_sip;
  resp_arp_hdr->ar_sip = sr_if->ip;
  
  result = sr_send_packet(sr, (uint8_t*)resp, len, interface);
  free(resp);
  return result;
}

int sr_handle_arp_reply(struct sr_instance *sr, struct sr_arp_hdr *arp_hdr) {
  struct sr_arpcache *cache = &(sr->cache);
  struct sr_ethernet_hdr *e_hdr = 0;
  unsigned char *next_hop_mac = arp_hdr->ar_sha;
  uint32_t ip = arp_hdr->ar_sip;
  struct sr_arpreq *req = 0;
  struct sr_packet *pkt = 0;

  pthread_mutex_lock(&(sr->cache.lock));

  req = arpcache_insert(cache, next_hop_mac, ip);
  if (req && req->packets) {
    for (pkt = req->packets; pkt; pkt = pkt->next) {
       e_hdr = (sr_ethernet_hdr_t*)(pkt->buf);
       memcpy(e_hdr->ether_dhost, next_hop_mac, ETHER_ADDR_LEN);
       sr_send_packet(sr, pkt->buf, pkt->len, pkt->iface);
    }
    /* TODO 只有全部发送成功才destroy，否则只删除发送成功的pkt */
    arpreq_destroy(cache, req);
  } 

  pthread_mutex_unlock(&(sr->cache.lock));
  return 0; 
}

int sr_send_arp_req(struct sr_instance *sr, char *sha, uint32_t sip, uint32_t tip, char *iface) {
  uint8_t *packet = 0;
  struct sr_ethernet_hdr *e_hdr= 0;
  struct sr_arp_hdr *a_hdr = 0;
  char *broadcast = "\xff\xff\xff\xff\xff\xff";
  int result = 0;
  int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
  packet = malloc(len);
  e_hdr = (struct sr_ethernet_hdr*)packet;
  memcpy(e_hdr->ether_shost, sha, ETHER_ADDR_LEN);
  memcpy(e_hdr->ether_dhost, broadcast, ETHER_ADDR_LEN);
  e_hdr->ether_type = htons(ethertype_arp);

  a_hdr = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
  a_hdr->ar_hrd = htons(arp_hrd_ethernet);
  a_hdr->ar_pro = htons(0x0800);
  a_hdr->ar_hln = ETHER_ADDR_LEN;
  a_hdr->ar_pln = 4; 
  a_hdr->ar_op = htons(arp_op_request); 
  memcpy(a_hdr->ar_tha, broadcast, ETHER_ADDR_LEN);
  memcpy(a_hdr->ar_sha, sha, ETHER_ADDR_LEN);
  a_hdr->ar_tip = tip;
  a_hdr->ar_sip = sip;
  
  result = sr_send_packet(sr, packet, len, iface); 
  free(packet);
  return result;
}

void sr_handle_arpreq(struct sr_instance *sr, struct sr_arpreq *req) {
  pthread_mutex_lock(&(sr->cache.lock));
  time_t curtime = time(NULL);
  struct sr_if *sr_if = sr_get_interface(sr, req->packets->iface); 
  struct sr_packet *pkt = 0;
  struct sr_ip_hdr *ip_hdr = 0;
  uint8_t *packet_to_send = 0;
  uint32_t ip_dst = 0;
  uint32_t next_hop_ip = 0;
  unsigned int len = 0;
  char iface_out[sr_IFACE_NAMELEN];

  if (difftime(curtime, req->sent) >= 1) {
    if (req->times_sent < 5) {
      sr_send_arp_req(sr, (char*)(sr_if->addr), sr_if->ip, req->ip, sr_if->name);
      req->sent = time(NULL);
      req->times_sent++;
    }
    else {
      for (pkt=req->packets; pkt; pkt=pkt->next) {
        ip_hdr = (sr_ip_hdr_t*)(pkt->buf + sizeof(sr_ethernet_hdr_t));
        ip_dst = ip_hdr->ip_src;
        len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
        packet_to_send = malloc(len);
        sr_find_next_hop_ip_and_iface(sr->routing_table, ip_dst, &next_hop_ip, iface_out);
        sr_fill_in_icmp_hostunreachable(sr, packet_to_send, pkt->buf, iface_out); 
        sr_arpcache_queuereq(&(sr->cache), next_hop_ip, packet_to_send, len, iface_out);
        free(packet_to_send);
      } 
      arpreq_destroy(&(sr->cache), req);
    }
  }
  pthread_mutex_unlock(&(sr->cache.lock));
}
