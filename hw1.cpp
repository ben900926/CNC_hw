#include <iostream>
#include <stdlib.h>
#include <pcap/pcap.h> 
#include <string.h>
#include <vector>
#include <netinet/udp.h> // for packet structure
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h> // ipv4 header
#define MIN(a,b)(a<b?a:b)
using namespace std;

uint16_t little_endian16(uint16_t num){
    uint16_t ans = 0;
    ans += (num & 0xff00) >> 8;
    ans += (num & 0x00ff) << 8;
    return ans;
}

uint32_t little_endian32(uint32_t num){
    uint32_t ans = 0;
    ans += (num & 0xff000000) >> 24;
    ans += (num & 0x00ff0000) >> 8;
    ans += (num & 0x0000ff00) << 8;
    ans += (num & 0x000000ff) << 24;
    return ans;
}

void parse_udp(const unsigned char* packet){
    struct udphdr udp_hdr;
    memcpy(&udp_hdr, packet, sizeof(struct udphdr));
    packet += sizeof(struct udphdr);
    // ------------transmission header-----------------
    // port
    printf("Source port: %d\n", little_endian16(udp_hdr.source));
    printf("Destination port: %d\n", little_endian16(udp_hdr.dest)); 
    //little_endian16(udp_hdr.len));
    // payload (first 16 byte)
    uint16_t len = little_endian16(udp_hdr.len);
    if(len > 8){
        printf("Payload: ");
        for(int i=0; i<MIN(len-8,16); i++){
            printf("%x ", *(packet+i));
        }
        printf("\n");
    }
}

void parse_tcp(const unsigned char* packet, uint16_t len){
    struct tcphdr tcp_hdr;
    memcpy(&tcp_hdr, packet, sizeof(struct tcphdr));
    packet += sizeof(struct tcphdr);
    // port
    printf("Source port: %d\n", little_endian16(tcp_hdr.source));
    printf("Destination port: %d\n", little_endian16(tcp_hdr.dest)); 
    
    len = len - tcp_hdr.doff * 4;  
    if(len > 0){
        printf("Payload: ");
        for(int i=0; i<MIN(len, 16); i++){
            printf("%x ", *(packet+i+12));
        }
        printf("\n");        
    }
}

void parse_icmp(const unsigned char* packet){
   struct icmphdr icmp_hdr;
   memcpy(&icmp_hdr, packet, sizeof(struct icmphdr));
   printf("ICMP type value: %d\n", icmp_hdr.type);
}

int main(int argc, const char * argv[]) 
{
    pcap_if_t *devices = NULL; 
    char errbuf[PCAP_ERRBUF_SIZE];
    char ntop_buf[256];
    struct ether_header *eptr;
    vector<pcap_if_t*> vec; // vec is a vector of pointers pointing to pcap_if_t 
    
    // deal with arguments
    // interface
    char* my_device = (char*)malloc(100);
    if(argc<=1){
        printf("wrong command\n");
        return -1;
    }
    // count
    int count = -1;
    
    // pcap filter
    char* my_filter = (char*)malloc(500);
    // strcpy(my_filter, "icmp and ip host 172.18.0.2");
    
    for(int i=1; i<argc; i+=2){
        if(strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--interface") == 0){
            strcpy(my_device, argv[i+1]);
        }
        else if(strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--count") == 0){
            count = atoi(argv[i+1]);
        }
        else if(strcmp(argv[i], "-f") == 0 || strcmp(argv[i], "--filter") == 0){
            strcpy(my_filter, argv[i+1]);
            if(strcmp(argv[i+1], "all") == 0 || strcmp(argv[i+1], "all\n") == 0){
                strcpy(my_filter, "tcp or udp or icmp");
            }
        }
        else{
            printf("unknown argument: %s\n", argv[i]);
            return -1;
        }

    }
    printf("\n");

    //get all devices 
    if(-1 == pcap_findalldevs(&devices, errbuf)) {
        fprintf(stderr, "pcap_findalldevs: %s\n", errbuf); // if error, fprint error message --> errbuf
        exit(1);
    }

    // list all device
    // int cnt = 0;
    /* 
    for(pcap_if_t *d = devices; d ; d = d->next, cnt++)
    {
        vec.push_back(d);
        cout<<"Name: "<<d->name<<endl;
    }
    */
    // open the device for sniffing
    struct bpf_program fp; // for filter, compiled in "pcap_compile"
    pcap_t *handle;

    handle = pcap_open_live(my_device, 65535, 1, 1, errbuf);  
    //pcap_open_live(device, snaplen, promise, to_ms, errbuf), interface is your interface, type is "char *"   
    
    if(!handle|| handle == NULL)
    {
        fprintf(stderr, "pcap_open_live(): %s\n", errbuf);
        exit(1);
    }

    if(-1 == pcap_compile(handle, &fp, my_filter, 1, PCAP_NETMASK_UNKNOWN) ) // compile "your filter" into a filter program, type of {your_filter} is "char *"
    {
        pcap_perror(handle, "pkg_compile compile error\n");
        exit(1);
    }
    if(-1 == pcap_setfilter(handle, &fp)) { // make it work
        pcap_perror(handle, "set filter error\n");
        exit(1);
    }

    // structure for header
    struct pcap_pkthdr* header;
    struct iphdr ipv4_hdr;
    /*
    transport type; src, dst ip; src, dst port, payload (if any)
    */
    while(1) 
    {   
        // keep grabing a packet
        const unsigned char* packet;
        pcap_next_ex(handle, &header, &packet);
        // parsing data: udp
        // print out
        /* 
        for(int i=14; i<header->len; i++)
            printf("%x ", *(packet+i));
        printf("\n ---------------- \n");
        */
        packet += 14;
        memcpy(&ipv4_hdr, packet, sizeof(struct iphdr));
        packet += sizeof(struct iphdr);

        // ------ Ipv4 header ---------------------
        // filter protocol
        printf("Transport type: ");
        if(ipv4_hdr.protocol == 0x11){
            // udp
            printf("UDP\n");
        }else if(ipv4_hdr.protocol == 0x06){
            printf("TCP\n");
        }else if(ipv4_hdr.protocol == 0x01){
            printf("ICMP\n");
        }else{
            printf("Unknown\n");
        }

        //memcpy(&udp_hdr, packet, sizeof(struct udphdr));
        //packet += sizeof(struct udphdr);
        // source addr
        uint32_t saddr = ipv4_hdr.saddr;
        printf("Source IP: ");
        for(int i=0; i<4; i++){
            if(i) printf("."); 
            printf("%d",(saddr & 0x000000ff) );
            saddr = saddr >> 8;
        }
        // dest addr
        printf("\nDestination IP: ");
        uint32_t daddr = ipv4_hdr.daddr;
        for(int i=0; i<4; i++){
            if(i) printf("."); 
            printf("%d",(daddr & 0x000000ff) );
            daddr = daddr >> 8;
        }
        printf("\n");
        if(ipv4_hdr.protocol == 0x11){
            // udp
            parse_udp(packet);
        }else if(ipv4_hdr.protocol == 0x06){
            parse_tcp(packet, little_endian16(ipv4_hdr.tot_len) - ipv4_hdr.ihl*4);
        }else if(ipv4_hdr.protocol == 0x01){
            parse_icmp(packet);
        }else{
            printf("Unknown\n");
        }
        printf("\n");
        // ------------transmission header-----------------
 
        if(count != -1){
            count--;
            if(count <= 0){
                break;
            }
        }
    }

    // close the session
    pcap_close(handle);

    pcap_freealldevs(devices);

    return 0;
    
}

// sudo tcpdump -ni lo <filter fules> -w test.pcap 