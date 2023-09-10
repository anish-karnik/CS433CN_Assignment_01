#include <stdio.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h> 

struct flow {
    char client_ip[INET_ADDRSTRLEN];
    char server_ip[INET_ADDRSTRLEN];
    unsigned int client_port;
    unsigned int server_port;
};

struct flow *flows = NULL;
int num_flows = 0;

// Signal handler for Ctrl+C
void handle_sigint(int signum) {
    printf("\nTotal number of flows observed: %d\n", num_flows);
    
    
    for (int i = 0; i < num_flows; i++) {
        printf("Flow %d: %s:%u -> %s:%u\n", i + 1, flows[i].client_ip, flows[i].client_port, flows[i].server_ip, flows[i].server_port);
    }
    
    exit(0);
}

int compare_flow(const void *a, const void *b) {
    const struct flow *flow_a = (const struct flow *)a;
    const struct flow *flow_b = (const struct flow *)b;
    
    int cmp_ip = strcmp(flow_a->client_ip, flow_b->client_ip);
    if (cmp_ip != 0) return cmp_ip;
    
    if (flow_a->client_port < flow_b->client_port) return -1;
    if (flow_a->client_port > flow_b->client_port) return 1;
    
    cmp_ip = strcmp(flow_a->server_ip, flow_b->server_ip);
    if (cmp_ip != 0) return cmp_ip;
    
    if (flow_a->server_port < flow_b->server_port) return -1;
    if (flow_a->server_port > flow_b->server_port) return 1;
    
    return 0;
}

void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    struct ip *ip_header;
    struct tcphdr *tcp_header;
    

    ip_header = (struct ip *)(packet + 14); 
    tcp_header = (struct tcphdr *)(packet + 14 + (ip_header->ip_hl << 2)); 
    

    char client_ip[INET_ADDRSTRLEN];
    char server_ip[INET_ADDRSTRLEN];
    unsigned int client_port, server_port;
    
    inet_ntop(AF_INET, &(ip_header->ip_src), client_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), server_ip, INET_ADDRSTRLEN);
    
    client_port = ntohs(tcp_header->th_sport);
    server_port = ntohs(tcp_header->th_dport);

 
    int found = 0;
    for (int i = 0; i < num_flows; i++) {
        if (strcmp(flows[i].client_ip, client_ip) == 0 &&
            strcmp(flows[i].server_ip, server_ip) == 0 &&
            flows[i].client_port == client_port &&
            flows[i].server_port == server_port) {
            found = 1;
            break;
        }
    }

  
    if (!found) {
       
        struct flow *new_flow = realloc(flows, (num_flows + 1) * sizeof(struct flow));
        if (new_flow == NULL) {
            fprintf(stderr, "Memory allocation failed.\n");
            exit(1);
        }
        
     
        strcpy(new_flow[num_flows].client_ip, client_ip);
        strcpy(new_flow[num_flows].server_ip, server_ip);
        new_flow[num_flows].client_port = client_port;
        new_flow[num_flows].server_port = server_port;
        
      
        flows = new_flow;
        
        
        num_flows++;
    }
}

int main(int argc, char *argv[]) {
    char *dev = "eth0"; 
    
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

 
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open network interface '%s': %s\n", dev, errbuf);
        return 1;
    }

   
    signal(SIGINT, handle_sigint);


    pcap_loop(handle, 0, packet_handler, NULL);


    pcap_close(handle);
    
    return 0;
}
