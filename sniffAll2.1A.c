//2.1A
// sniffing packets without filter
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include "netinet/ip.h"
//#include <sys/ioctl.h>
//#include <linux/if.h>
//#include <linux/if_ether.h>
//
#define SIZE_ETHERNET 14
//
//struct ifreq ethreq;
//
//void my_cleanup(){
//    ethreq.i
//}

/*This function will be invoked by pcap for each captured packet.
 * We can process each packet inside the function.*/
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct iphdr *ip; // build a iphdr struct to get access to the ip addresses.
    struct sockaddr_in address; // will contain the source+dest addr
    ip = (struct iphdr *) (packet + SIZE_ETHERNET); // modify ip
    memset(&address, 0, sizeof(address));
    address.sin_addr.s_addr = ip->saddr;// modify source

    printf("Got a packet\n");
    char *src = inet_ntoa(address.sin_addr);// converting source to fine ip address
    printf("src ip: %s\n", src);
    address.sin_addr.s_addr = ip->daddr;// modify dest
    char *dst = inet_ntoa(address.sin_addr);// converting dest to fine ip address
    printf("dst ip: %s\n", dst);
}

int main() {

    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Step 1: Open live pcap session on NIC with name "br-3bef0344ba07"
    handle = pcap_open_live("br-3bef0344ba07", BUFSIZ, 0, 1000, errbuf); //1 or zero to turn promisc on/off.


    // Step 2: Capture packets
    pcap_loop(handle, -1, got_packet, NULL); // -1 for infinity captures
    pcap_close(handle);

    //Close the handle
    return 0;
}

// Note: don’t forget to add "-lpcap" to the compilation command.
// For example: gcc -o sniff sniff.c -lpcap
