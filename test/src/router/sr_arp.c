#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*find the values on the ip address bit and count the non zero values inside the ip*/
int length_of_prefix(uint32_t ip){
    int length = 0;
    uint32_t mask = ntohl(ip);
    /*keep and the mask with 10000000 00000000 00000000 00000000 to check if the first bit is 1*/
    while (mask & 0x80000000) {
        length++;
        /*move the mask left by one*/
        mask <<= 1;
    }

    return length;

}

/*find the longest prefix match routing table entry for this destination ip*/
struct sr_rt* find_node(struct sr_instance* s, uint32_t dest_ip) {
    struct sr_rt* returned  = NULL;
    int max_len = -1; 
    struct sr_rt* h = s->routing_table;
    while (h != NULL) {
        if ((dest_ip & h->mask.s_addr) == (h->dest.s_addr & h->mask.s_addr)) {
            int prefix_length = length_of_prefix(h->mask.s_addr);
            /*if the mask is the longer than the previous mask, we replace it with the longer mask*/
            if (prefix_length > max_len) {
                max_len = prefix_length;
                returned = h;
            }
        }
        h = h->next;
    }
    return returned;
}


/*dest_ip*/
/*send arp request on one request queue*/
int send_arp_request(struct sr_instance* s, struct sr_arpreq* req){
    if(s==NULL){
        printf("there is no sr_instance here");
        return 1;
    }
    struct sr_rt* dest_route = find_node(s, req->ip);
    /*sending the arp request to the dest_ip's next hop*/
    struct sr_arp_hdr* arph = (struct sr_arp_hdr*) malloc(sizeof(struct sr_arp_hdr));
    struct sr_if* source = sr_get_interface(s, req->packets->iface);

    arph->ar_hrd = htons(arp_hrd_ethernet);
    arph->ar_pro= htons(ethertype_ip);
    arph->ar_hln = ETHER_ADDR_LEN;
    arph->ar_pln = 4;                   /*since we use ipv4 here*/
    arph->ar_op = htons(arp_op_request);
    memset(arph->ar_tha, 255, sizeof(uint8_t)*ETHER_ADDR_LEN);
    memcpy(arph->ar_sha, source->addr, sizeof(uint8_t)*ETHER_ADDR_LEN);
    arph->ar_sip = source->ip;
    arph->ar_tip = req->ip;


    /*set the target hardware address to be broadcase hardware address*/    
    struct sr_ethernet_hdr* ethh = (struct sr_ethernet_hdr*) malloc(sizeof(struct sr_ethernet_hdr));
    ethh->ether_type = htons(ethertype_arp);
    memset(ethh->ether_dhost, 255, sizeof(uint8_t)*ETHER_ADDR_LEN); /*?*/
    memcpy(ethh->ether_shost, source->addr, sizeof(uint8_t)*ETHER_ADDR_LEN);

    unsigned int length = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr);
    uint8_t* buffer = (uint8_t*) malloc(length);
    if(buffer==NULL){
        fprintf(stderr, "Memory allocation failure in buffer");
        free(arph);
        free(ethh);
        return 1;
    }
    /* Copy the headers into the buffer */
    memcpy(buffer, ethh, sizeof(struct sr_ethernet_hdr));
    /* buffer + sizeof(struct sr_ethernet_hdr) make sure the arp header are copied just after ethernet header */
    memcpy(buffer + sizeof(struct sr_ethernet_hdr), arph, sizeof(struct sr_arp_hdr));


    print_hdrs(buffer,length);
    int res = sr_send_packet(s, buffer, length, dest_route->interface);

    free(arph);
    free(ethh);


    if (res!=0){
        printf("arp request fail in sending packet process");
        return 1;
    }
    return 0;
}

/*send all packets on one arp request queue by using the mac address in the arp reply header*/
void send_packet_on_arpreq(struct sr_instance* sr, struct sr_packet* h, struct sr_arp_hdr* arph){
    if(h==NULL){
        return;
    }
    struct sr_ethernet_hdr* eth_header = (struct sr_ethernet_hdr*) h->buf;

    /*copy the destination mac address into the ethernet header*/
    memcpy(eth_header->ether_shost, arph->ar_tha, sizeof(uint8_t) * ETHER_ADDR_LEN);
    memcpy(eth_header->ether_dhost, arph->ar_sha, sizeof(uint8_t) * ETHER_ADDR_LEN);

    /*send the packet*/
    if(sr_send_packet(sr, h->buf, h->len, h->iface)!=0){
        fprintf(stderr, "error in sending the packet on arp request queue");
    }

    /*loop through the queue to send every packet there*/
    send_packet_on_arpreq(sr, h->next, arph);
}

/*handle the arp reply and send the packet inside the request queue if needed*/
void handle_arp_reply(struct sr_instance* sr, struct sr_arp_hdr* arph)
{
    /*check if the request is alreay inside the queue*/
    struct sr_arpreq* request =  sr_arpcache_insert(&sr->cache, arph->ar_sha, arph->ar_sip);
    if(request!=NULL){
        struct sr_packet *packets = request->packets;
        if(packets!=NULL){
            send_packet_on_arpreq(sr, packets, arph);
        }
        sr_arpreq_destroy(&sr->cache, request);
    }
}
