
#include<netinet/in.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<netinet/ip_icmp.h>
#include<netinet/ip.h>
#include<net/ethernet.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include <linux/if_packet.h>
#include <unistd.h>

void filter_icmp_and_print(unsigned char *buf);

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    printf("Got a packet\n");
}

//
//https://stackoverflow.com/questions/14837453/how-to-sniff-all-icmp-packets-using-raw-sockets
int main() {
    int PACKET_LEN = IP_MAXPACKET;
//    unsigned char buffer[PACKET_LEN];
    struct sockaddr saddr;
    struct packet_mreq mr;

    // Create the raw socket
//    int sock = socket(AF_INET, SOCK_RAW, htons(ETH_P_ALL));//IPPROTO_ICMP
//    int sock = socket(AF_PACKET, SOCK_RAW, htons(IPPROTO_ICMP));//IPPROTO_ICMP
//    int sock = socket(AF_INET , SOCK_RAW , IPPROTO_ICMP);
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));//reciv
//    int sock = socket(AF_INET , SOCK_RAW , IPPROTO_TCP);
//    int sock = socket(PF_INET , SOCK_RAW , IPPROTO_TCP);

    printf("socket = %d\n", sock);
    if (sock == -1) {
        perror("sock Error");
        return 1;
    }

    //promiscuous mode does not work in our machine

    // Getting captured packets
    while (1) {

        unsigned char buffer[IP_MAXPACKET]={0};
//        for (int j=0;)
//        memset(&buffer, 0, PACKET_LEN);
//        printf("memset\n");
        size_t sizeof_addres = sizeof(saddr);
        int data_size = recvfrom(sock, buffer, PACKET_LEN, 0, &saddr, (socklen_t *) &sizeof_addres);
//        int data_size = recvfrom(sock_raw , buffer , 65536 , 0 , &saddr , &saddr_size);

//        printf("recvfrom=%d\n", data_size);

        if (data_size >= 0) {

//            printf("Got one packet: \n");

            filter_icmp_and_print(buffer);
        }
//        break;
    }
    close(sock);
    return 0;
}

void filter_icmp_and_print(unsigned char *buf) {

    struct iphdr *iph = (struct iphdr *)(buf  + sizeof(struct ethhdr));
    sockaddr_in temp;
    if (iph->protocol == IPPROTO_ICMP) {
        printf("\n\nICMP PACKET\n");
        temp.sin_addr.s_addr = iph->saddr;

        unsigned int iphdrlen = iph->ihl * 4;

        printf("IP_SRC : %s\n", inet_ntoa(temp.sin_addr));

        temp.sin_addr.s_addr = iph->daddr;
        printf("IP_DST : %s\n", inet_ntoa(temp.sin_addr));


        struct icmphdr *icmph = (struct icmphdr *) (buf + iphdrlen + sizeof(struct ethhdr));

//        int type = (int)icmph->type;
//        if (type == 8 ){
//            printf("TYPE : %d \n", type);
//        }
        uint8_t type = icmph->type;
        printf("TYPE : %d", type);
        if (type == 8){
            printf(" Echo request\n");
        }
        if (type == 0){
            printf(" Echo reply\n");
        }
        printf("CODE : %d\n", icmph->code);

    }

}