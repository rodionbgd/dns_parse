#include <memory.h>
#include <pcap.h>
#include "src/dns_parser.h"
#include <arpa/inet.h>

/**
@brief Вывод данных пакета DNS
@param DNS - данные пакета DNS
*/
void dns_print(DNS* dns) {
    if(!(dns->ip_length[0]))
        return;
    int i = 0;
    char ip[64];
    printf("%s\n", dns->name);
    while(dns->ip_length[i]) {
        if(dns->ip_length[i] == 4)
            inet_ntop(AF_INET, &dns->ip[i++], ip, INET_ADDRSTRLEN);
        else
            inet_ntop(AF_INET6, &dns->ip[i++], ip, INET6_ADDRSTRLEN);
        printf("%s\t", ip);
    }
    printf("\n");
}

/**
@brief Обработка пакетов
@return 0 - OK, -1 - Error
 */
int dns_parser() {
    char errbuf[PCAP_ERRBUF_SIZE];
    const uint8_t* packet;
    pcap_t* p;
    struct pcap_pkthdr* hdr = NULL;
    struct bpf_program bpf;
    bpf_u_int32 maskp = 0xFFFFFF;
    char in[]         = "../dns_in.pcap";
    //    char in[] = "../dns.cap";

    p = pcap_open_offline(in, errbuf);
    if(!p) {
        return -1;
    }
    if(pcap_compile(p, &bpf, "port 53", 0, maskp) == PCAP_ERROR) {
        return -1;
    }
    if(pcap_setfilter(p, &bpf) == PCAP_ERROR) {
        return -1;
    }
    DNS dns = {};
    uint16_t dns_length;
    while(pcap_next_ex(p, &hdr, &packet) >= 0) {
        dns_length = hdr->caplen;
        memset(&dns, 0, sizeof(dns));
        dns_handle(packet + 42, dns_length, &dns);
        dns_print(&dns);
    }
    return 0;
}

int main() {
    dns_parser();
    return 0;
}