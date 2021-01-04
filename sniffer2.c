
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

int main() {
    int PACKET_LEN = 512;
    char buffer[PACKET_LEN];
    struct sockaddr saddr;
    struct packet_mreq mr;

    // Create the raw socket
    int sock = socket(AF_PACKET, SOCK_RAW, IPPROTO_ICMP);//htons(ETH_P_ALL)

    // Turn on the promiscuous mode.
    mr.mr_type = PACKET_MR_PROMISC;
    setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr,
               sizeof(mr));

    // Getting captured packets
    while (1) {
        memset(&buffer, 0, PACKET_LEN);
        int data_size = recvfrom(sock, buffer, PACKET_LEN, 0, &saddr, (socklen_t *) sizeof(saddr));
        if (data_size!=-1) printf("Got one packet: %s\n", buffer+20);
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
