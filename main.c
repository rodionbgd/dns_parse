#include <memory.h>
#include <pcap.h>
#include "src/dns_parser.h"

/**
@brief Вывод данных пакета DNS
@param DNS - данные пакета DNS
*/
void dns_print(DNS *dns) {
    if (!dns)
        return;
    printf("Transaction ID: 0x%x\n", dns->header.id);
    printf("Flags:\n");
    printf("%d... .... .... .... = Response\n", dns->header.qr);
    printf(".%03d %d... .... .... = Opcode\n", dns->header.opcode >> 1u, dns->header.opcode & 0x1u);
    printf(".... ..%d. .... .... = Truncated\n", dns->header.tc);
    printf(".... ...%d .... .... = Recursion\n", dns->header.rd);
    printf(".... .... .%03d .... = Z\n", dns->header.z);
    printf(".... .... .... %04d = Reply code\n", dns->header.rcode);
    printf("Questions: %d\n", dns->header.qdcount);
    printf("Answer RRs: %d\n", dns->header.ancount);
    printf("Authority RRs: %d\n", dns->header.nscount);
    printf("Additional RRs: %d\n", dns->header.arcount);
    uint16_t count = dns->header.ancount + dns->header.nscount + dns->header.arcount;

    if (!dns->response)
        return;
    for (int i = 0; i < count; i++) {
        if (i == dns->header.ancount - 1)
            printf("Answers\n");
        else if (i == dns->header.nscount - 1)
            printf("Authority\n");
        else if (i == dns->header.arcount - 1)
            printf("Additional\n");
        printf("Name: %s\n", dns->response[i].answer_name);
        printf("Type: %d\n", dns->response[i].type);
        printf("Class: 0x%x\n", dns->response[i].class_);
        printf("TTL: %d\n", dns->response[i].ttl);
        printf("Data length: %d\n", dns->response[i].rdlength);
        if (dns->response[i].type != SOA) {
            printf("Data: %s\n\n", dns->response[i].rdata);
        } else {
            //           printf("Primary name server: %s\n", dns->response[i].soa.rname);
            printf("Mailbox: %s\n", dns->response[i].soa.mname);
            printf("Serial number: %d\n", dns->response[i].soa.serial);
            printf("Refresh interval: %d\n", dns->response[i].soa.refresh);
            printf("Retry interval: %d\n", dns->response[i].soa.retry);
            printf("Expire limit: %d\n", dns->response[i].soa.expire);
            printf("Minimum TTL: %d\n\n", dns->response[i].soa.ttl);
        }
    }
}

/**
@brief Обработка пакетов
@return 0 - OK, -1 - Error
 */
int dns_parser() {
    char errbuf[PCAP_ERRBUF_SIZE];
    const uint8_t *packet;
    pcap_t *p;
    struct pcap_pkthdr *hdr = NULL;
    struct bpf_program bpf;
    bpf_u_int32 maskp = 0xFFFFFF;
//    char in[] = "../dns_in.pcap";
    char in[] = "../dns.cap";

    p = pcap_open_offline(in, errbuf);
    if (!p) {
        return -1;
    }
    if (pcap_compile(p, &bpf, "port 53", 0, maskp) == PCAP_ERROR) {
        return -1;
    }
    if (pcap_setfilter(p, &bpf) == PCAP_ERROR) {
        return -1;
    }
    DNS dns = {};
    uint16_t dns_length;
    while (pcap_next_ex(p, &hdr, &packet) >= 0) {
        dns_length = hdr->caplen;
        dns_handle(packet + 42, dns_length, &dns);
        dns_print(&dns);
    }
    return 0;
}

int main() {
    dns_parser();
    return 0;
}