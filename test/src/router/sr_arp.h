#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

struct sr_rt* find_node(struct sr_instance* s, uint32_t dest_ip);
int send_arp_request(struct sr_instance* s, uint32_t dest_ip);
void send_packet_on_arpreq(struct sr_instance* sr, struct sr_packet* h, unsigned char dest_mac[]);
void handle_arp_reply(struct sr_instance* sr, struct sr_arp_hdr* arph);
