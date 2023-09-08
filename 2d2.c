#include <stdio.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <string.h>

#define IP_HEADER_SIZE 20

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

   
    handle = pcap_open_offline("pc1.pcap", errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
        return 1;
    }

  
    int source_port_to_match = 10987;

   
    struct pcap_pkthdr header;
    const unsigned char *packet;

    while ((packet = pcap_next(handle, &header)) != NULL) {
        struct ip *ip_header = (struct ip *)(packet + 14); 

        struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + IP_HEADER_SIZE);

       
        if (ntohs(tcp_header->th_sport) == source_port_to_match) {
            
            printf("Source IP: %s\n", inet_ntoa(ip_header->ip_src));
            printf("Source Port: %d\n", ntohs(tcp_header->th_sport));
            printf("Destination IP: %s\n", inet_ntoa(ip_header->ip_dst));
            printf("Destination Port: %d\n", ntohs(tcp_header->th_dport));

           
            printf("TCP Payload Data:\n");
            int payload_size = header.caplen - (14 + IP_HEADER_SIZE + (tcp_header->th_off << 2));
            if (payload_size > 0) {
                printf("%.*s\n\n", payload_size, packet + 14 + IP_HEADER_SIZE + (tcp_header->th_off << 2));
            } else {
                printf("No TCP payload data.\n\n");
            }
        }
    }

    pcap_close(handle);

    return 0;
}
