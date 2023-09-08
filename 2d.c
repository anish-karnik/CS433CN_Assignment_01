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


    char target_ip[] = "123.134.156.178";
    struct in_addr target_ip_addr;
    if (inet_pton(AF_INET, target_ip, &target_ip_addr) != 1) {
        fprintf(stderr, "Invalid target IP address format\n");
        return 1;
    }


    handle = pcap_open_offline("pc1.pcap", errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
        return 1;
    }


    pcap_loop(handle, 0, process_packet, (u_char *)&target_ip_addr);

    pcap_close(handle);
    return 0;
}

void process_packet(u_char *user, const struct pcap_pkthdr *header, const unsigned char *packet) {
    struct ip *ip_header = (struct ip *)(packet + 14); 


    char src_ip[INET_ADDRSTRLEN];
    char dest_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dest_ip, INET_ADDRSTRLEN);


    struct in_addr *target_ip_addr = (struct in_addr *)user;
    if (ip_header->ip_src.s_addr == target_ip_addr->s_addr) {
       
        struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + IP_HEADER_SIZE);


        int ports_sum = ntohs(tcp_header->th_sport) + ntohs(tcp_header->th_dport);


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


        printf("Sum of Ports: %d\n", ports_sum);


        int tcp_data_offset = 14 + IP_HEADER_SIZE + (tcp_header->th_off << 2);
        printf("TCP Payload Data:\n");
        printf("%.*s\n\n", (int)(header->caplen - tcp_data_offset), packet + tcp_data_offset);
    }
}
