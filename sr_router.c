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
#include <time.h>
#include <arpa/inet.h>
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
void handle_arp(struct sr_instance* sr,
    sr_arp_hdr_t* packet/* lent */,
    unsigned int len,
    struct sr_if* interface/* lent */);
void handle_ip(struct sr_instance* sr,
    sr_ip_hdr_t* packet,
    unsigned int len,
    struct sr_if* interface);
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
    if(len < sizeof(sr_ethernet_hdr_t)) return;
    struct sr_if* recvIf = sr_get_interface(sr, interface);
    switch(ethertype(packet)){
        case ethertype_arp:
            handle_arp(sr,
                       (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t)),
                       len - sizeof(sr_ethernet_hdr_t),
                       recvIf);
            break;
        case ethertype_ip:
            handle_ip(sr,
                      (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t)),
                      len - sizeof(sr_ethernet_hdr_t),
                      recvIf);
            break;
        default: return;
    }
}


void set_ip_hdr_checksum(sr_ip_hdr_t *ipHdr){
    ipHdr->ip_sum = 0;
    ipHdr->ip_sum = cksum(ipHdr, ipHdr->ip_hl * 4u);
}


/* returns 1 if one of the interfaces has a ip that is equal to ipaddr */
int sr_has_ipaddr(struct sr_instance *sr, uint32_t ipaddr){
    struct sr_if *curr = sr->if_list;
    while (curr != NULL){
        if(curr->ip == ipaddr) return 1;
        curr = curr->next;
    }
    return 0;
}
/* Returns the length of the subnet mask in bits */
unsigned int get_mask_length(uint32_t mask){
    unsigned int total = 0;
    int i = 0;
    for(; i < 32; i++){
        if((mask & (1 << i)) == (1 << i)){
            total++;
        }
    }
    return total;
}

struct sr_rt* longest_prefix_match(struct sr_instance *sr, uint32_t ip){
    struct sr_rt *best = NULL;
    struct sr_rt *curr = sr->routing_table;
    while (curr != NULL){
        if ((ip & curr->mask.s_addr) == (curr->dest.s_addr & curr->mask.s_addr)){
            if(best == NULL || get_mask_length(best->mask.s_addr) < get_mask_length(curr->mask.s_addr)){
                best = curr;
            }
        }
        curr = curr->next;
    }
    return best;
}

/* initialize the common fields of an ethernet packet encapsulating an ip packet
 * bodyLength is the length of the ip packet payload in bytes.
 * UPON FINISHING EXECUTION:
 * - the value of pToPacket will point to the address of the complete packet
 * - the value of pToEtherPtr will point to the address of the ethernet header
 * - the value of pToIpPtr will point to the address of the IP header
 * - the length of the complete packet will be returned
 * You must call free() on the ptr that pToPacket points to once you no longer need the packet.
 * */
unsigned int init_ether_ip_packet(unsigned int bodyLength,
                                  uint8_t **pToPacket,
                                  sr_ethernet_hdr_t **pToEtherPtr,
                                  sr_ip_hdr_t **pToIpPtr){
    unsigned int size = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + bodyLength;
    uint8_t * packet = malloc(size);
    sr_ethernet_hdr_t *ethernetHdr = (sr_ethernet_hdr_t*)packet;
    ethernetHdr->ether_type = htons(ethertype_ip);

    sr_ip_hdr_t  *ipHdr = (sr_ip_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t));
    ipHdr->ip_v = 4;
    ipHdr->ip_hl = sizeof(sr_ip_hdr_t) / 4;
    ipHdr->ip_tos = 0;
    ipHdr->ip_len = htons(sizeof(sr_ip_hdr_t) + bodyLength);
    ipHdr->ip_id = 0;
    ipHdr->ip_off = htons(IP_DF);
    ipHdr->ip_ttl = 64;
    *pToPacket = packet;
    *pToEtherPtr = ethernetHdr;
    *pToIpPtr = ipHdr;
    return size;
}

void send_ether_frame_with_ip_payload(struct sr_instance *sr,
                                      sr_ethernet_hdr_t *frame /* lent */,
                                      struct sr_rt *routeToUse){
    sr_ip_hdr_t *ipHdr = (sr_ip_hdr_t*)((void*)frame + sizeof(sr_ethernet_hdr_t));
    set_ip_hdr_checksum(ipHdr);
    struct sr_if *interfaceToUse = sr_get_interface(sr, routeToUse->interface);
    /*
     * frame->ether_type = ethertype_ip;
     * (not needed, already set in init_ether_ip_packet)
     */
    memcpy(frame->ether_shost, interfaceToUse->addr, ETHER_ADDR_LEN);
    uint32_t nextHopIp;
    if(routeToUse->gw.s_addr == 0){
        nextHopIp = ipHdr->ip_dst;
    }
    else{
        nextHopIp = routeToUse->gw.s_addr;
    }
    unsigned int length = ntohs(ipHdr->ip_len) + sizeof(sr_ethernet_hdr_t);
    struct sr_arpentry *arpEntry = sr_arpcache_lookup(&sr->cache, nextHopIp);
    if (arpEntry == NULL){
        struct sr_arpreq *arpreq = sr_arpcache_queuereq(&sr->cache,
                                                        nextHopIp,
                                                        (uint8_t*)frame,
                                                        length,
                                                        routeToUse->interface);
        handle_arpreq(sr, arpreq);
    }
    else{
        memcpy(frame->ether_dhost, arpEntry->mac, ETHER_ADDR_LEN);
        sr_send_packet(sr, (uint8_t*)frame, length, routeToUse->interface);
        free(arpEntry);
    }
}

/* send a icmp dest unreachable packet to original sender. No need to free anything. */
void perform_send_icmp_unreachable(struct sr_instance *sr,
                                   enum sr_dest_unreachable_code code,
                                   sr_ip_hdr_t *origPacket){
    if(sr_has_ipaddr(sr, origPacket->ip_src)){
        return;
    }
    uint8_t *response;
    sr_ethernet_hdr_t *respEthernet;
    sr_ip_hdr_t  *respIp;
    init_ether_ip_packet(sizeof(sr_icmp_t3_hdr_t),
                         &response,
                         &respEthernet,
                         &respIp);
    sr_icmp_t3_hdr_t *respIcmp  = ((void*)respIp) + sizeof(sr_ip_hdr_t);
    respIp->ip_dst = origPacket->ip_src;
    respIp->ip_p = ip_protocol_icmp;
    respIcmp->icmp_type = icmp_dest_unreachable;
    respIcmp->icmp_code = code;
    respIcmp->icmp_sum = 0;
    respIcmp->unused = 0;
    respIcmp->next_mtu = 0;
    memcpy(respIcmp->data, origPacket, ICMP_DATA_SIZE);
    respIcmp->icmp_sum = cksum(respIcmp, sizeof(sr_icmp_t3_hdr_t));
    struct sr_rt *routeToUse = longest_prefix_match(sr, respIp->ip_dst);
    /* Since we've received the packet, we should know how to route it back.
     * Thus, it is highly unlikely for the following line to happen.
     * */
    if(routeToUse == NULL) return;
    struct sr_if *outIf = sr_get_interface(sr, routeToUse->interface);
    if(code == dest_port_unreachable){
        respIp->ip_src = origPacket->ip_dst;
    }
    else{
        respIp->ip_src = outIf->ip;
    }
    set_ip_hdr_checksum(respIp);
    send_ether_frame_with_ip_payload(sr, respEthernet, routeToUse);
    free(response);
}

/* send a icmp ttl exceeded packet to original sender. No need to free anything. */
void perform_send_icmp_time_exceed(struct sr_instance *sr,
        sr_ip_hdr_t *origPacket){
    uint8_t *response;
    sr_ethernet_hdr_t *respEthernet;
    sr_ip_hdr_t  *respIp;
    init_ether_ip_packet(sizeof(sr_icmp_t3_hdr_t),
                         &response,
                         &respEthernet,
                         &respIp);
    /*
     * Although we are sending a time exceeded message, the icmp header struct for
     * type 3 messages (destination unreachable) suits our purpose well, so we're
     * reusing it here.
     */
    sr_icmp_t3_hdr_t *respIcmp  = ((void*)respIp) + sizeof(sr_ip_hdr_t);
    respIp->ip_dst = origPacket->ip_src;
    respIp->ip_p = ip_protocol_icmp;

    respIcmp->icmp_type = icmp_time_exceeded;
    respIcmp->icmp_code = 0;
    respIcmp->icmp_sum = 0;
    respIcmp->unused = 0;
    respIcmp->next_mtu = 0;
    memcpy(respIcmp->data, origPacket, ICMP_DATA_SIZE);
    respIcmp->icmp_sum = cksum(respIcmp, sizeof(sr_icmp_t3_hdr_t));
    struct sr_rt *routeToUse = longest_prefix_match(sr, respIp->ip_dst);
    /* Since we've received the packet, we should know how to route it back.
     * Thus, it is highly unlikely for the following line to happen.
     * */
    if(routeToUse == NULL) return;
    struct sr_if *outIf = sr_get_interface(sr, routeToUse->interface);
    respIp->ip_src = outIf->ip;
    set_ip_hdr_checksum(respIp);
    send_ether_frame_with_ip_payload(sr, respEthernet, routeToUse);
    free(response);
}
/* initialize the common fields of an ethernet packet encapsulating an arp packet
 * sendingIf points to the interface we will use to send this packet. Needed to set MAC address.
 * UPON FINISHING EXECUTION:
 * - the value of pToPacket will point to the address of the complete packet
 * - the value of pToEtherPtr will point to the address of the ethernet header
 * - the value of pToArpPtr will point to the address of the ARP header
 * - the length of the complete packet will be returned
 * You must call free() on the ptr that pToPacket points to once you no longer need the packet.
 * */
unsigned int init_ether_arp_packet(struct sr_if *sendingIf,
                                   uint8_t **pToPacket,
                                   sr_ethernet_hdr_t **pToEtherPtr,
                                   sr_arp_hdr_t **pToArpPtr){
    unsigned int size = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    uint8_t * packet = malloc(size);
    sr_ethernet_hdr_t *ethernetHdr = (sr_ethernet_hdr_t*)packet;

    ethernetHdr->ether_type = htons(ethertype_arp);
    memcpy(ethernetHdr->ether_shost, sendingIf->addr, ETHER_ADDR_LEN);

    sr_arp_hdr_t *arpHdr = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
    arpHdr->ar_hrd = htons(arp_hrd_ethernet);
    arpHdr->ar_pro = htons(ethertype_ip);
    arpHdr->ar_hln = ETHER_ADDR_LEN;
    arpHdr->ar_pln = IP_ADDR_LEN;
    memcpy(arpHdr->ar_sha, sendingIf->addr, ETHER_ADDR_LEN);
    arpHdr->ar_sip = sendingIf->ip;
    *pToPacket = packet;
    *pToEtherPtr = ethernetHdr;
    *pToArpPtr = arpHdr;
    return size;
}

void handle_arp(struct sr_instance* sr,
                sr_arp_hdr_t* packet/* lent */,
                unsigned int len,
                struct sr_if* interface/* lent */){
    if(len < sizeof(sr_arp_hdr_t)) return;
    if(ntohs(packet->ar_op) == arp_op_request && packet->ar_tip == interface->ip){
        uint8_t *response;
        sr_ethernet_hdr_t  *respEthernet;
        sr_arp_hdr_t *respArp;
        unsigned int size = init_ether_arp_packet(interface, &response, &respEthernet, &respArp);
        memcpy(respEthernet->ether_dhost, packet->ar_sha, ETHER_ADDR_LEN);

        respArp->ar_op = htons(arp_op_reply);
        respArp->ar_tip = packet->ar_sip;
        memcpy(respArp->ar_tha, packet->ar_sha, ETHER_ADDR_LEN);

        sr_send_packet(sr, response, size, interface->name);
        free(response);
    }
    else if(ntohs(packet->ar_op) == arp_op_reply){
        struct sr_arpreq *arpRequest = sr_arpcache_insert(&sr->cache, packet->ar_sha, packet->ar_sip);
        if(arpRequest == NULL) return;
        struct sr_packet *curr = arpRequest->packets;
        while(curr != NULL){
            sr_ethernet_hdr_t *currEthernetHdr = (sr_ethernet_hdr_t*)curr->buf;
            memcpy(currEthernetHdr->ether_dhost, packet->ar_sha, ETHER_ADDR_LEN);
            sr_send_packet(sr, curr->buf, curr->len, curr->iface);
            struct sr_packet *next = curr->next;
            curr = next;
        }
        sr_arpreq_destroy(&sr->cache, arpRequest);
    }
}



/* Handles ip packets destined for the some other host that the router should forward to */
void handle_ip_forward(struct sr_instance* sr,
                       sr_ip_hdr_t* packet,
                       unsigned int len,
                       struct sr_if* interface){
    uint16_t checksum_cpy = packet->ip_sum;
    packet->ip_sum = 0;
    set_ip_hdr_checksum(packet);
    if (checksum_cpy != packet->ip_sum) return;
    struct sr_rt *routeToUse = longest_prefix_match(sr, packet->ip_dst);
    if(routeToUse == NULL){
        perform_send_icmp_unreachable(sr, dest_net_unreachable, packet);
        return;
    }
    packet->ip_ttl--;
    if(packet->ip_ttl == 0){
        perform_send_icmp_time_exceed(sr, packet);
        return;
    }
    sr_ethernet_hdr_t *ethernetHdr = (void*)packet - sizeof(sr_ethernet_hdr_t);
    send_ether_frame_with_ip_payload(sr, ethernetHdr, routeToUse);
}


/* Handles icmp packets destined for the router itself */
void handle_ip_icmp(struct sr_instance* sr,
                    sr_ip_hdr_t* packet,
                    unsigned int len,
                    struct sr_if* interface){
    if(len - packet->ip_hl * 4 < sizeof(sr_icmp_hdr_t)) return;
    sr_icmp_hdr_t *icmpHdr = (sr_icmp_hdr_t*)((uint8_t*)packet + packet->ip_hl * 4u);
    uint16_t checksum_cpy = icmpHdr->icmp_sum;
    icmpHdr->icmp_sum = 0;
    if(cksum(icmpHdr, len - packet->ip_hl * 4) != checksum_cpy ) return;
    /* We only need to handle echo requests for this assignment */
    if(icmpHdr->icmp_type != icmp_echo_request){
        return;
    }
    unsigned int respBodyLen = len - packet->ip_hl * 4u;

    uint8_t *response;
    sr_ethernet_hdr_t *respEthernetHdr;
    sr_ip_hdr_t  *respIpHdr;
    init_ether_ip_packet(respBodyLen,
        &response,
        &respEthernetHdr,
        &respIpHdr);
    respIpHdr->ip_src = packet->ip_dst;
    respIpHdr->ip_dst = packet->ip_src;
    respIpHdr->ip_p = ip_protocol_icmp;
    sr_icmp_hdr_t  *respIcmpHdr = (sr_icmp_hdr_t*)(response + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    memcpy((void*)respIcmpHdr + sizeof(sr_icmp_hdr_t),
           (void*)packet + packet->ip_hl * 4u + sizeof(sr_icmp_hdr_t),
           respBodyLen - sizeof(sr_icmp_hdr_t));
    respIcmpHdr->icmp_type = icmp_echo_reply;
    respIcmpHdr->icmp_code = 0;
    respIcmpHdr->icmp_sum = 0;
    respIcmpHdr->icmp_sum = cksum(respIcmpHdr, respBodyLen);
    struct sr_rt *routeToUse = longest_prefix_match(sr, respIpHdr->ip_dst);
    /* Since we've received the packet, we should know how to route it back.
     * Thus, it is highly unlikely for the following line to happen.
     * */
    if(routeToUse == NULL) return;
    send_ether_frame_with_ip_payload(sr, respEthernetHdr, routeToUse);
    free(response);
}

/* Handles non-icmp ip packets destined for the router itself */
void handle_ip_self(struct sr_instance* sr,
                    sr_ip_hdr_t* packet,
                    unsigned int len,
                    struct sr_if* interface){
    perform_send_icmp_unreachable(sr, dest_port_unreachable, packet);
}



void handle_ip(struct sr_instance* sr,
                sr_ip_hdr_t* packet,
                unsigned int len,
                struct sr_if* interface){
    if(len < MIN_IP_HDR_LEN) return;
    if(sr_has_ipaddr(sr, packet->ip_dst)){
        if(packet->ip_p == ip_protocol_icmp) {
            handle_ip_icmp(sr, packet, len, interface);
        }
        else{
            handle_ip_self(sr, packet, len, interface);
        }
    }
    else{
        handle_ip_forward(sr, packet, len, interface);
    }
}

void handle_arpreq(struct sr_instance *sr, struct sr_arpreq *req){
    time_t now = time(NULL);
    if(difftime(now, req->sent) < 1.0) return;
    if (req->times_sent >= 5)
    {
        struct sr_packet *packet;
        for(packet = req->packets; packet != NULL; packet = packet->next){
            perform_send_icmp_unreachable(sr, dest_host_unreachable,
                                          (void *) packet->buf + sizeof(sr_ethernet_hdr_t));
        }
        sr_arpreq_destroy(&sr->cache, req);
    }
    else {
        uint8_t *request;
        sr_ethernet_hdr_t  *requestEther;
        sr_arp_hdr_t *requestArp;
        /*
         * I hate how this is done but the starter code is structured this way
         */
        struct sr_if *interface = sr_get_interface(sr, req->packets[0].iface);
        unsigned int size = init_ether_arp_packet(interface, &request, &requestEther, &requestArp);
        memset(requestEther->ether_dhost, 0xFF, ETHER_ADDR_LEN);
        requestArp->ar_op = htons(arp_op_request);
        requestArp->ar_tip = req->ip;
        memset(requestArp->ar_tha, 0, ETHER_ADDR_LEN);
        sr_send_packet(sr, request, size, interface->name);
        free(request);
        req->times_sent++;
        req->sent = time(NULL);
    }
}