//2.1C
//sniffing telnet packets
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "netinet/ip.h"
#include "netinet/tcp.h"

#define SIZE_ETHERNET 14

/*This function will be invoked by pcap for each captured packet.We can process each packet inside the function.*/
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct iphdr *ip; // build a iphdr struct to get access to the ip addresses.
    struct tcphdr *tcp;
    struct sockaddr_in address; // will contain the source+dest addr
    char *payload; // eth(ip(tcp(payload)))
    unsigned int payload_len = header->len - (sizeof(struct iphdr) + sizeof (struct tcphdr));
    ip = (struct iphdr *) (packet + SIZE_ETHERNET); // modify ip
    memset(&address, 0, sizeof(address));
    tcp = (struct tcphdr*) (packet + SIZE_ETHERNET+ sizeof(struct iphdr)); // modify ip

    payload = (char*)(packet+ SIZE_ETHERNET+ sizeof(struct iphdr) + sizeof (struct tcphdr)+12);



    address.sin_addr.s_addr = ip->saddr;// modify source

    printf("Got a packet\n");
    char *src = inet_ntoa(address.sin_addr);// converting source to fine ip address
    printf("src ip: %s\n", src);
    address.sin_addr.s_addr = ip->daddr;// modify dest
    char *dst = inet_ntoa(address.sin_addr);// converting dest to fine ip address
    printf("dst ip: %s\n", dst);
    if(payload_len){
        printf("payload : \n");
        for (int i = 0; i < payload_len; ++i) {

            if(isprint(payload[i]))
                printf("%c",payload[i]);
            else{
                break;
            }
        }
        printf("\n");
    }
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp && dst port 23";
    bpf_u_int32 net;

    // Step 1: Open live pcap session on NIC with name br-3bef0344ba07
    handle = pcap_open_live("br-3bef0344ba07", BUFSIZ, 1, 1000, errbuf);

    // Step 2: Compile filter_exp into BPF psuedo-code
    pcap_compile(handle, &fp, filter_exp, 0, net);
    pcap_setfilter(handle, &fp);

    // Step 3: Capture packets
    pcap_loop(handle, -1, got_packet, NULL);
    pcap_close(handle);

    //Close the handle
    return 0;
}

// Note: don’t forget to add "-lpcap" to the compilation command.
// For example: gcc -o sniff sniff.c -lpcap
