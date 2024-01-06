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
#include <string.h>
#include <stdlib.h>




#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#include "sr_arp.h"

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


int sr_send_icmp(struct sr_instance* sr /* borrowed */,
                 uint8_t* packet /* lent */,
                 unsigned int len,
                 char* interface  /* lent */,
                 uint8_t icmp_type,
                 uint8_t icmp_code,
                 uint32_t ip_src,
                 uint32_t ip_dst,
                 uint8_t* ether_shost,
                 uint8_t* ether_dhost) {
    fprintf(stdout, "this is send_icmp\n");
    print_hdrs(packet, len);
    unsigned int hdr_len = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_hdr);
    unsigned int data_len = 0;
    struct sr_ip_hdr *ip_hdr = (struct sr_ip_hdr *)(packet + sizeof(struct sr_ethernet_hdr));
    /* If ICMP reply, data should include payload of received ICMP echo */
    if (icmp_type == 0) {
      data_len = len - hdr_len;
      fprintf(stdout, "cksum(data)=%d\n", cksum(packet + hdr_len, data_len));
    }
    /* If ICMP error, data should include IP header and everything else inside received packet */
    else {
      data_len = ntohs(ip_hdr->ip_len);
      fprintf(stdout, "cksum(data)=%d\n", cksum(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr), data_len));
    }

    fprintf(stdout, "len=%d, new_len=hdr_len + data_len=%d + %d=%d\n", len, hdr_len, data_len, hdr_len + data_len);
    uint8_t *reply_packet = malloc(hdr_len + data_len);
    memcpy(reply_packet, packet, sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));

    struct sr_ethernet_hdr *reply_eth_hdr = (sr_ethernet_hdr_t*)(reply_packet);
    struct sr_ip_hdr *reply_ip_hdr = (sr_ip_hdr_t*)(reply_packet+sizeof(sr_ethernet_hdr_t));
    struct sr_icmp_hdr *reply_icmp_hdr = (sr_icmp_hdr_t*)(reply_packet+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));

    fprintf(stdout, "Copying data ");
    if (icmp_type == 0) {
      fprintf(stdout, "from reply...\n");
      memcpy(reply_packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_hdr), 
      packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_hdr), data_len);
    }
    else {
      fprintf(stdout, "from msg...\n");
      memcpy(reply_packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_hdr), 
      packet + sizeof(struct sr_ethernet_hdr), data_len);
    }

    fprintf(stdout, "Modifying icmp header...\n");
    reply_icmp_hdr->icmp_type = icmp_type;
    reply_icmp_hdr->icmp_code = icmp_code;
    reply_icmp_hdr->icmp_sum = 0;
    reply_icmp_hdr->icmp_sum = cksum(reply_icmp_hdr, sizeof(struct sr_icmp_hdr) + data_len);

    fprintf(stdout, "Modifying ip header...\n");
    reply_ip_hdr->ip_ttl = 64;
    reply_ip_hdr->ip_p = ip_protocol_icmp;
    reply_ip_hdr->ip_len = htons(sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_hdr) + data_len);
    reply_ip_hdr->ip_src = ip_src;
    reply_ip_hdr->ip_dst = ip_dst;
    reply_ip_hdr->ip_sum = 0;
    reply_ip_hdr->ip_sum = cksum(reply_ip_hdr, sizeof(struct sr_ip_hdr));

    fprintf(stdout, "Modifying ethernet header...\n");
    memcpy(reply_eth_hdr->ether_dhost, ether_dhost, sizeof(uint8_t)*ETHER_ADDR_LEN);
    memcpy(reply_eth_hdr->ether_shost, ether_shost, sizeof(uint8_t)*ETHER_ADDR_LEN);

    printf("------Send ICMP (%d)------\n", hdr_len+data_len);
    print_hdrs(reply_packet, hdr_len + data_len);
    if (icmp_type != 0) {
      /*print_hdr_ip(reply_packet + hdr_len);
      print_hdr_icmp(reply_packet + hdr_len + sizeof(struct sr_ip_hdr));*/
    }
    if (sr_send_packet(sr, reply_packet, hdr_len+data_len, interface) == -1) {
        fprintf(stderr, "** Error: error sending packet len %d\n", hdr_len+data_len);
        free(reply_packet);
        return 0;
    }
    free(reply_packet);
    return 1;
}

void sr_send_icmp3(int type, int code, struct sr_instance *sr, uint8_t *packet, char *interface) {
  /* Initialize all reply header */
  struct sr_if *receive_if = sr_get_interface(sr, interface);


  unsigned int icmp3_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_icmp_t3_hdr_t) + sizeof(sr_ip_hdr_t);
  uint8_t *reply_packet = malloc(icmp3_len);
  sr_icmp_t3_hdr_t *reply_icmp_hdr = (sr_icmp_t3_hdr_t *)(reply_packet + sizeof(struct sr_ip_hdr) + sizeof(struct sr_ethernet_hdr));
  struct sr_ip_hdr *reply_ip_hdr = (struct sr_ip_hdr *)(reply_packet + sizeof(struct sr_ethernet_hdr));
  struct sr_ethernet_hdr *eth_hdr = (struct sr_ethernet_hdr *)(reply_packet);

  /* Ethernet Header */
  memcpy(eth_hdr->ether_shost, receive_if->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
  memcpy(eth_hdr->ether_dhost, ((struct sr_ethernet_hdr *)(packet))->ether_shost, sizeof(uint8_t) * ETHER_ADDR_LEN); 
  eth_hdr->ether_type = htons(ethertype_ip);
  

  /* IP Header */
  reply_ip_hdr->ip_v = 4;
  reply_ip_hdr->ip_hl = sizeof(sr_ip_hdr_t) / 4;
  reply_ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
  reply_ip_hdr->ip_tos = 0;
  reply_ip_hdr->ip_id = 0;
  reply_ip_hdr->ip_off = htons(IP_DF);
  reply_ip_hdr->ip_ttl = 64;
  reply_ip_hdr->ip_p = ip_protocol_icmp;
  reply_ip_hdr->ip_dst = ((sr_ip_hdr_t *)(packet + sizeof(struct sr_ethernet_hdr)))->ip_src;
  reply_ip_hdr->ip_src = ((sr_ip_hdr_t *)(packet + sizeof(struct sr_ethernet_hdr)))->ip_dst;
  if (code != 3) 
      reply_ip_hdr->ip_src = receive_if->ip;

  reply_ip_hdr->ip_sum = 0;
  reply_ip_hdr->ip_sum = cksum(reply_ip_hdr, sizeof(sr_ip_hdr_t));

  /* ICMP Header */
  reply_icmp_hdr->icmp_type = type;
  reply_icmp_hdr->icmp_code = code;
  reply_icmp_hdr->next_mtu = 0;
  reply_icmp_hdr->unused = 0;
  memcpy(reply_icmp_hdr->data, packet + sizeof(struct sr_ethernet_hdr), sizeof(uint8_t) * ICMP_DATA_SIZE);
  reply_icmp_hdr->icmp_sum = 0;
  reply_icmp_hdr->icmp_sum = cksum(reply_icmp_hdr, sizeof(sr_icmp_t3_hdr_t));

  print_hdrs(reply_packet, icmp3_len);
  sr_send_packet(sr, reply_packet, icmp3_len, receive_if->name);
}


void sr_handlepacket_IP(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
    struct sr_if* iface = sr_get_interface(sr, interface);
    struct sr_ip_hdr* receive_ip_hdr = 0;
    struct sr_ethernet_hdr *receive_eth_hdr = 0;
    /*struct sr_icmp_hdr* receive_icmp_hdr = 0;  NOT USED*/

    receive_eth_hdr = (struct sr_ethernet_hdr*) (packet);
    receive_ip_hdr = (struct sr_ip_hdr*)(packet+sizeof(struct sr_ethernet_hdr));
    /*receive_icmp_hdr = (struct sr_icmp_hdr*)(packet+sizeof(struct sr_ethernet_hdr)+sizeof(struct sr_ip_hdr)); NOT USED*/ 

    /* Check that ip_packet satisfies minimum length*/
    if (len < sizeof(struct sr_ip_hdr)) {
        return;
    }

    /* Check that ip_packet->ip_sum is correct*/
    uint16_t ip_sum = receive_ip_hdr->ip_sum;
    receive_ip_hdr->ip_sum = 0;
    if (cksum ((void *)receive_ip_hdr, sizeof(sr_ip_hdr_t)) != ip_sum) {
        return;
    }
    receive_ip_hdr->ip_sum = ip_sum;

    if(receive_ip_hdr->ip_ttl == 1){
      sr_send_icmp3(11, 0,sr, packet, interface);
      return;
    }

    assert(iface);
    /*Packet is sent to itself*/
    int temp = 0;
    struct sr_if *if_list = sr->if_list;
    while(if_list){
      if(receive_ip_hdr->ip_dst == if_list->ip){
        temp = 1;
        break;
      }
      if_list = if_list->next;
    }
    


    if (temp) {
        /*ICMP*/
        if (receive_ip_hdr->ip_p == ip_protocol_icmp) {
            sr_send_icmp(sr, packet, len, interface, 0, 0, receive_ip_hdr->ip_dst, receive_ip_hdr->ip_src, receive_eth_hdr->ether_dhost, receive_eth_hdr->ether_shost);
        }
        /*TCP/UDP*/
        else {
            /*sr_send_icmp(sr, packet, len, interface, 3, 3, receive_ip_hdr->ip_dst, receive_ip_hdr->ip_src, receive_eth_hdr->ether_dhost, receive_eth_hdr->ether_shost);*/
            sr_send_icmp3(3, 3, sr, packet, interface);
        }
    }

    else{
      printf("Forward packet\n");
      /*Packet is sent to someone else */
      receive_ip_hdr->ip_ttl--;
      receive_ip_hdr->ip_sum = 0;
      receive_ip_hdr->ip_sum = cksum ((void *)receive_ip_hdr, sizeof(sr_ip_hdr_t));



      if(find_node(sr, receive_ip_hdr->ip_dst) == NULL){
        fprintf(stderr,"Not in RT\n");
        sr_send_icmp3(3, 0, sr, packet, interface);
        return;
      }

      struct sr_rt* receive_rt = find_node(sr, receive_ip_hdr->ip_dst);
      struct sr_if *receive_rt_if = sr_get_interface(sr, receive_rt->interface);
      memcpy(receive_eth_hdr->ether_shost, receive_rt_if->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);

      struct sr_arpcache *cache = &(sr->cache);
      struct sr_arpentry* entry = sr_arpcache_lookup(cache, receive_ip_hdr->ip_dst);

      if((entry) == NULL) {
        /*We don't have mac address for the destination, add to queue*/
        struct sr_arpreq *req = sr_arpcache_queuereq(&(sr->cache), receive_ip_hdr->ip_dst, packet, len, receive_rt_if->name);
        handle_arpreq(sr, req);
      }
      else{
        /*Found mac address, forward the packet*/
        memcpy(receive_eth_hdr->ether_dhost, entry->mac, sizeof(uint8_t)*ETHER_ADDR_LEN);
        sr_send_packet(sr, packet, len, receive_rt->interface);
      }
    }
}

void sr_handlepacket_ARP(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  printf("------Handling ARP packet------\n");
  /*Read 
  Received ethernet header,
  Received arp header,
  Received interface*/
  struct sr_ethernet_hdr *receive_eth_hdr;
  receive_eth_hdr = (struct sr_ethernet_hdr*) (packet);
  struct sr_arp_hdr *receive_arp_hdr;
  receive_arp_hdr = (struct sr_arp_hdr*) (packet+sizeof(struct sr_ethernet_hdr));
  struct sr_if* receive_if;
  receive_if = sr_get_interface(sr, interface);
  
  if(htons(receive_arp_hdr-> ar_op) == arp_op_request){
    
    
    
    /*initialize reply packet*/
    uint8_t *reply_packet = malloc(len);
    memcpy(reply_packet, packet, len);
    struct sr_ethernet_hdr *reply_eth_hdr = (sr_ethernet_hdr_t*)(reply_packet);
    struct sr_arp_hdr *reply_arp_hdr = (sr_arp_hdr_t*)(reply_packet+sizeof(sr_ethernet_hdr_t));

    /*renew ethernet header info*/
    memcpy(reply_eth_hdr->ether_dhost, receive_eth_hdr->ether_shost, sizeof(uint8_t)*ETHER_ADDR_LEN);
    memcpy(reply_eth_hdr->ether_shost, receive_if->addr, sizeof(uint8_t)*ETHER_ADDR_LEN);
    reply_eth_hdr->ether_type = ntohs(ethertype_arp);

    /*renew arp header info*/
    reply_arp_hdr->ar_op = ntohs(arp_op_reply);
    memcpy(reply_arp_hdr->ar_sha, receive_if->addr, sizeof(uint8_t)*ETHER_ADDR_LEN);
    reply_arp_hdr->ar_sip = receive_arp_hdr->ar_tip;
    memcpy(reply_arp_hdr->ar_tha, receive_arp_hdr->ar_sha, sizeof(uint8_t)*ETHER_ADDR_LEN);
    reply_arp_hdr->ar_tip = receive_arp_hdr->ar_sip;
    /*print_hdrs(reply_packet, len);*/
    
    sr_send_packet(sr, reply_packet, len, interface);
    
  }
  else{
    handle_arp_reply(sr, receive_arp_hdr);
  }
}

/*---------------------------------------------------------------------*/
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

  if(ethertype(packet) == ethertype_ip){
    /*Handle IP Packet*/
    printf("Receive a IP packet\n");
    sr_handlepacket_IP(sr, packet, len, interface);
  }
  else{
    /*Handle ARP Packet*/
    printf("Receive a ARP packet\n");
    sr_handlepacket_ARP(sr, packet, len, interface);
  }
}/* end sr_ForwardPacket */
