
#include<netinet/in.h>
#include<stdio.h>
#include<string.h>
#include<netinet/ip_icmp.h>
#include<netinet/ip.h>
#include<net/ethernet.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include <linux/if_packet.h>
#include <unistd.h>

void filter_icmp_and_print(char *buf);


// this artical helps us to understand how we need uses the raw socket and sniff the icmp header
//https://stackoverflow.com/questions/14837453/how-to-sniff-all-icmp-packets-using-raw-sockets
int main() {
    int PACKET_LEN = IP_MAXPACKET;
    struct sockaddr saddr;
    struct packet_mreq mr;

    // Create the raw socket with access to all protocols
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    //check if the socket create properly
    if (sock == -1) {
        perror("sock Error");
        return 1;
    }

    //promiscuous mode does not work in our machine so we did not added it to our code

    // Getting captured packets
    while (1) {
        //the buffer collect each packet at the time
        char buffer[IP_MAXPACKET] = {0};

        size_t sizeof_addres = sizeof(saddr);
        // receive packet from raw socket
        int packet_size = recvfrom(sock, buffer, PACKET_LEN, 0, &saddr, (socklen_t *) &sizeof_addres);

        if (packet_size >= 0){
            filter_icmp_and_print(buffer);
        }
    }
    close(sock);
    return 0;
}

void filter_icmp_and_print(char *buf) {
    struct iphdr *iph = (struct iphdr *) (buf + sizeof(struct ethhdr));
    sockaddr_in temp;

    // Checks if the current packet is ICMP packet
    if (iph->protocol == IPPROTO_ICMP) {
        printf("\n\nICMP PACKET\n");
        unsigned int iphdrlen = iph->ihl * 4;

        temp.sin_addr.s_addr = iph->saddr;
        printf("IP_SRC : %s\n", inet_ntoa(temp.sin_addr));

        temp.sin_addr.s_addr = iph->daddr;
        printf("IP_DST : %s\n", inet_ntoa(temp.sin_addr));

        struct icmphdr *icmph = (struct icmphdr *) (buf + iphdrlen + sizeof(struct ethhdr));

        uint8_t type = icmph->type;
        printf("TYPE : %d", type);
        if (type == 8) {
            printf(" Echo request\n");
        }
        if (type == 0) {
            printf(" Echo reply\n");
        }
        printf("CODE : %d\n", icmph->code);
    }
}