
void print_icmp_packet(unsigned char* Buffer , int Size)
{
    unsigned short iphdrlen;

    struct iphdr *iph = (struct iphdr *)Buffer;
    iphdrlen = iph->ihl*4;

    struct icmphdr *icmph = (struct icmphdr *)(Buffer + iphdrlen);

    fprintf(logfile,"\n\n***********************ICMP Packet*************************\n");

    print_ip_header(Buffer , Size);

    fprintf(logfile,"\n");

    fprintf(logfile,"ICMP Header\n");
    fprintf(logfile,"   |-Type : %d",(unsigned int)(icmph->type));

    if((unsigned int)(icmph->type) == 11)
        fprintf(logfile,"  (TTL Expired)\n");
    else if((unsigned int)(icmph->type) == ICMP_ECHOREPLY)
        fprintf(logfile,"  (ICMP Echo Reply)\n");
    fprintf(logfile,"   |-Code : %d\n",(unsigned int)(icmph->code));
    fprintf(logfile,"   |-Checksum : %d\n",ntohs(icmph->checksum));
    //fprintf(logfile,"   |-ID       : %d\n",ntohs(icmph->id));
    //fprintf(logfile,"   |-Sequence : %d\n",ntohs(icmph->sequence));
    fprintf(logfile,"\n");

    fprintf(logfile,"IP Header\n");
    PrintData(Buffer,iphdrlen);

    fprintf(logfile,"UDP Header\n");
    PrintData(Buffer + iphdrlen , sizeof icmph);

    fprintf(logfile,"Data Payload\n");
    PrintData(Buffer + iphdrlen + sizeof icmph , (Size - sizeof icmph - iph->ihl * 4));

    fprintf(logfile,"\n###########################################################");
}


































//#include "headers.h"
//#include <pcap/pcap.h>
//#include <cstdio>
//#include <stdio.h>
//#include <stdlib.h>
//#include <unistd.h>
//#include <string.h>
//#include <sys/types.h>
//#include <sys/socket.h>
//#include <netinet/in.h>
//#include <netinet/ip.h>
//#include <netinet/ip_icmp.h>
//#include <arpa/inet.h>
//#include <errno.h>
//#include <sys/time.h> // gettimeofday()
//#include <netdb.h>
//#include <fcntl.h>
//
//#include <pcap.h>
//#include <stdio.h>
//
//void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
//    printf("Got a packet\n");
//}
//
//int main() {
//    pcap_t *handle;
//    char errbuf[PCAP_ERRBUF_SIZE];
//    struct bpf_program fp;
//    char filter_exp[] = "ip proto icmp";
//    bpf_u_int32 net;
//
//    // Step 1: Open live pcap session on NIC with name eth3
//    handle = pcap_open_live("eth3", BUFSIZ, 1, 1000, errbuf);
//
//    // Step 2: Compile filter_exp into BPF psuedo-code
//    pcap_compile(handle, &fp, filter_exp, 0, net);
//    pcap_setfilter(handle, &fp);
//
//    // Step 3: Capture packets
//    pcap_loop(handle, -1, got_packet, NULL);
//
//    pcap_close(handle);   //Close the handle
//    return 0;
//}