#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>

#define PACKET_BUFFER_SIZE 65536
#define IP_HEADER_SIZE 20

void process_packet(unsigned char *, int);

int main() {
    int raw_socket;
    struct sockaddr_in server;
    socklen_t server_len = sizeof(server);
    unsigned char packet_buffer[PACKET_BUFFER_SIZE];


    raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (raw_socket == -1) {
        perror("Socket creation error");
        exit(1);
    }


    while (1) {
        int packet_size = recvfrom(raw_socket, packet_buffer, PACKET_BUFFER_SIZE, 0, (struct sockaddr *)&server, &server_len);
        if (packet_size == -1) {
            perror("Packet receive error");
            close(raw_socket);
            exit(1);
        }

        process_packet(packet_buffer, packet_size);
    }

    close(raw_socket);
    return 0;
}

void process_packet(unsigned char *packet, int packet_size) {
    struct ip *ip_header = (struct ip *)(packet);
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + IP_HEADER_SIZE);

    char src_ip[INET_ADDRSTRLEN];
    char dest_ip[INET_ADDRSTRLEN];


    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dest_ip, INET_ADDRSTRLEN);


    printf("Source IP: %s\n", src_ip);
    printf("Source Port: %d\n", ntohs(tcp_header->th_sport));
    printf("Destination IP: %s\n", dest_ip);
    printf("Destination Port: %d\n", ntohs(tcp_header->th_dport));
    printf("\n");
}
