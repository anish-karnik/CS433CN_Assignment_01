#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <signal.h>
#include <unistd.h>

#define IP_HEADER_SIZE 20

void process_packet(unsigned char *, int);
void print_process_id_for_port(int port);

pcap_t *handle;
int running = 1;

void sigint_handler(int signum) {
    running = 0;
    pcap_breakloop(handle);
}

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    if (!running) {
        return;
    }

    process_packet((unsigned char *)packet, pkthdr->len);
}

int main() {
    signal(SIGINT, sigint_handler);
    
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs, *dev;
    
    // Get the list of available network interfaces
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding network interfaces: %s\n", errbuf);
        exit(1);
    }

    // Use the first network interface
    dev = alldevs;
    if (dev == NULL) {
        fprintf(stderr, "No network interfaces found.\n");
        exit(1);
    }

    // Open the selected network interface for packet capture
    handle = pcap_open_live(dev->name, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening network interface: %s\n", errbuf);
        exit(1);
    }
    
    // Free the list of network interfaces
    pcap_freealldevs(alldevs);

    while (running) {
        // Prompt the user for a port number
        printf("Enter a port number (Ctrl+C to exit): ");
        int port;
        if (scanf("%d", &port) != 1) {
            perror("Invalid input");
            exit(1);
        }
        
        // Start packet capture indefinitely
        pcap_loop(handle, 0, packet_handler, NULL);
        
        // Print the process ID for the entered port
        print_process_id_for_port(port);
        printf("\n");
    }

    pcap_close(handle);
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
}

void print_process_id_for_port(int port) {
    char command[100];
    sprintf(command, "lsof -t -i :%d", port);
    
    FILE *fp = popen(command, "r");
    if (fp == NULL) {
        perror("popen failed");
        return;
    }
    
    char output[50];
    if (fgets(output, sizeof(output), fp) != NULL) {
        printf("Process ID for port %d: %s", port, output);
    } else {
        printf("No process found for port %d\n", port);
    }
    
    pclose(fp);
}
