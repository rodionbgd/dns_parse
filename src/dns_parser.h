#ifndef DNS_PARSER_LIBRARY_H
#define DNS_PARSER_LIBRARY_H

#include <time.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif
// Значения поля TYPE в секциях Answer, Authority и Additional
enum DNS_TYPE {
    A = 1, NS, MD, MF, CNAME, SOA, MB, MG, MR, NULL_, WKS, PTR, HINFO, MINFO, MX, TXT, AAAA = 28
};

// Значения поля CLASS в секциях Answer, Authority и Additional
enum DNS_CLASS {
    IN = 1, CS, CH, HS
};

// Структура заголовка пакета DNS
typedef struct {
    const uint16_t id;
    const uint8_t rcode: 4;
    const uint8_t z: 3;
    const uint8_t ra: 1;
    const uint8_t rd: 1;
    const uint8_t tc: 1;
    const uint8_t aa: 1;
    const uint8_t opcode: 4;
    const uint8_t qr: 1;
    const uint16_t qdcount;
    const uint16_t ancount;
    const uint16_t nscount;
    const uint16_t arcount;
} DNS_header;

// Структура типа данных SOA в поле rdata
typedef struct {
    uint32_t serial;
    uint32_t refresh;
    uint32_t retry;
    uint32_t expire;
    uint32_t ttl;
    char mname[32];
    char rname[32];
} DNS_type_SOA;

// Структура секций Answer, Authority и Additional
#pragma pack(push,1)
typedef struct {
    uint16_t type;
    uint16_t class_;
    uint32_t ttl;
    uint16_t rdlength;
    union {
        char rdata[128];
        DNS_type_SOA soa;
    };
    char *answer_name;
} DNS_response;
#pragma pack(pop)
typedef struct {
    DNS_header header;
    DNS_response *response;
} DNS;

/**
@brief Очистка выделенной памяти для поля answer_name
@param dns - данные пакета DNS
*/
void dns_clean(DNS *dns);

/**
@brief Обработка пакета DNS
@param packet - пакет DNS
return структура Dns, с параметрами пакета, иначе NULL
*/
DNS *dns_handle(const unsigned char *packet);

#ifdef __cplusplus
}
#endif
#endif //DNS_PARSER_LIBRARY_H
