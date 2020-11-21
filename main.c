#include <memory.h>
#include <pcap.h>
#include "src/dns_parser.h"
#include <arpa/inet.h>
#include <uthash.h>

/**
@brief Вывод данных пакета DNS
@param DNS - данные пакета DNS
*/
void dns_print(DNS* dns) {
    if(!(dns->ip_type[0]))
        return;
    int i = 0;
    char ip[MAX_NAME_LENGTH];
    printf("%s\n", dns->name);
    while(dns->ip_type[i]) {
        if(dns->ip_type[i] == AF_INET)
            inet_ntop(AF_INET, &dns->ip[i++], ip, INET_ADDRSTRLEN);
        else
            inet_ntop(AF_INET6, &dns->ip[i++], ip, INET6_ADDRSTRLEN);
        printf("%s\t", ip);
    }
    printf("\n");
}

typedef struct {
    uint16_t num;
    char site[MAX_NAME_LENGTH];
    UT_hash_handle hh;
} DNS_stat;

int name_sort(DNS_stat* a, DNS_stat* b) {
    return a->num < b->num;
}

void dns_print_stat(DNS_stat* sites) {
    HASH_SRT(hh, sites, name_sort);
    DNS_stat* s;
    int i = 0;
    for(s = sites; s != NULL; s = s->hh.next) {
        printf("site: %-15s\tnum %d\n", s->site, s->num);
        if(++i >= NUM_SITES)
            break;
    }
    printf("\n");
}
void dns_stat(DNS* dns, DNS_stat** sites) {
    DNS_stat* s;
    uint16_t length = strlen(dns->name);
    uint8_t i       = 0;

    while(dns->name[length - i++] != '.')
        ;
    while(dns->name[length - i++] != '.' && length >= i)
        ;
    i = length < i ? length : i - 2;
    HASH_FIND_PTR(*sites, &dns->name[length - i], s);
    if(s == NULL) {
        s      = (DNS_stat*) malloc(sizeof(DNS_stat));
        s->num = 1;
        strcpy(s->site, &dns->name[length - i]);
        HASH_ADD_PTR(*sites, site, s);
    }
    else {
        s->num++;
    }
}

void clean(DNS_stat* sites) {
    DNS_stat *item, *tmp;
    HASH_ITER(hh, sites, item, tmp) {
        HASH_DEL(sites, item);
        free(item);
    }
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
    const char* in    = "../../examples_dns/dns_in.pcap";
    //    const char *in = "../../examples_dns/dns.cap";

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
    DNS_stat* sites     = NULL;
    uint32_t num_packet = 0;
    uint8_t is_packet;
    while(pcap_next_ex(p, &hdr, &packet) >= 0) {
        dns_length = hdr->caplen;
        memset(&dns, 0, sizeof(dns));
        is_packet = dns_handle(&packet[42], dns_length, &dns);
        if(!is_packet) {
            dns_stat(&dns, &sites);
            num_packet++;
        }
        if(num_packet % 10 == 0) {
            dns_print_stat(sites);
        }
   //     dns_print(&dns);
    }
    clean(sites);
    return 0;
}

int main() {
    dns_parser();
    return 0;
}