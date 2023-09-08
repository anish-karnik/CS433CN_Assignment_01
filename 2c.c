#include <stdio.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <string.h> 

#define IP_HEADER_SIZE 20

void process_packet(u_char *user, const struct pcap_pkthdr *header, const unsigned char *packet);

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;


    handle = pcap_open_offline("pc1.pcap", errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
        return 1;
    }


    pcap_loop(handle, 0, process_packet, NULL);

    pcap_close(handle);
    return 0;
}

void process_packet(u_char *user, const struct pcap_pkthdr *header, const unsigned char *packet) {
    struct ip *ip_header = (struct ip *)(packet + 14); 
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + IP_HEADER_SIZE);

    char src_ip[INET_ADDRSTRLEN];
    char dest_ip[INET_ADDRSTRLEN];


    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dest_ip, INET_ADDRSTRLEN);


    int tcp_data_offset = 14 + IP_HEADER_SIZE + (tcp_header->th_off << 2);


    uint16_t tcp_checksum = ntohs(tcp_header->th_sum);


    if (tcp_checksum == 0xf436) {

        printf("Source IP: %s\n", src_ip);
        printf("Source Port: %d\n", ntohs(tcp_header->th_sport));
        printf("Destination IP: %s\n", dest_ip);
        printf("Destination Port: %d\n", ntohs(tcp_header->th_dport));


        printf("TCP Flags: ");
        if (tcp_header->th_flags & TH_FIN) printf("FIN ");
        if (tcp_header->th_flags & TH_SYN) printf("SYN ");
        if (tcp_header->th_flags & TH_RST) printf("RST ");
        if (tcp_header->th_flags & TH_PUSH) printf("PSH ");
        if (tcp_header->th_flags & TH_ACK) printf("ACK ");
        if (tcp_header->th_flags & TH_URG) printf("URG ");
        printf("\n");


        printf("TCP Checksum: 0x%04X\n", tcp_checksum);

 
        printf("TCP Payload Data:\n");
        printf("%.*s\n\n", (int)(header->caplen - tcp_data_offset), packet + tcp_data_offset);
    }
}
