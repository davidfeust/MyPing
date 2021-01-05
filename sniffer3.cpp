
#include "headers.h"
#include <pcap/pcap.h>
//#include <cstdio>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/time.h> // gettimeofday()
#include <netdb.h>
#include <fcntl.h>

#include <pcap.h>
#include <stdio.h>

#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <stdio.h>

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    printf("Got a packet\n");
}

void icmp_print(char *packet){

    ICMP_Packet *icmpPacket ;
//    icmpPacket->

}
//https://stackoverflow.com/questions/14837453/how-to-sniff-all-icmp-packets-using-raw-sockets
//1 they have youer answer
int main() {
    int PACKET_LEN = IP_MAXPACKET;
    char buffer[PACKET_LEN];
    struct sockaddr saddr;
    struct packet_mreq mr;
    printf("packet_mreq\n");

    // Create the raw socket
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));//IPPROTO_ICMP
    printf("socket = %d\n", sock);
    if (sock == -1) {
        perror("sock Error");
        return 1;
    }

//    // Turn on the promiscuous mode.
    mr.mr_type = PACKET_MR_PROMISC;
    if (setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr)) == -1) {
        perror("promiscuous mode failed\n");
    }
    printf("mr_type\n");

    // Getting captured packets
int i =10;
    while (i){
        i++;
        memset(&buffer, 0, PACKET_LEN);
//        printf("memset\n");

        size_t sizeof_addres = sizeof(saddr);
        int data_size = recvfrom(sock, buffer, PACKET_LEN, 0, &saddr, (socklen_t *) &sizeof_addres);
//        printf("recvfrom\n");

        if (data_size >= 0) {
            printf("data_size\n");


            printf("Got one packet: %s\n", buffer);
        }
//        break;
    }

    close(sock);
    return 0;
}

/*printf("mail");
pcap_t *handle;
char errbuf[PCAP_ERRBUF_SIZE];
struct bpf_program fp;
char filter_exp[] = "ip proto icmp";
bpf_u_int32 net;

// Step 1: Open live pcap session on NIC with name eth3
handle = pcap_open_live("eth3", BUFSIZ, 1, 1000, errbuf);
printf("handle");

// Step 2: Compile filter_exp into BPF psuedo-code
pcap_compile(handle, &fp, filter_exp, 0, net);
pcap_setfilter(handle, &fp);
printf("pcap_compile");

// Step 3: Capture packets
pcap_loop(handle, -1, got_packet, NULL);
printf("pcap_loop");

pcap_close(handle);   //Close the handle
return 0;*/
