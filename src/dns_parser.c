#include "dns_parser.h"
#include <string.h>
#include <arpa/inet.h>
#include <ctype.h>

#define MAX_NAME_LENGTH 256
#define MAX_RESPONSE    12

// Значения поля TYPE в секциях Answer, Authority и Additional
enum DNS_TYPE { A = 1, NS, MD, MF, CNAME, SOA, MB, MG, MR, NULL_, WKS, PTR, HINFO, MINFO, MX, TXT, AAAA = 28 };

// Проверка на валидность символов из библиотеки NDPI
static uint32_t dns_validchar[8] = {0x00000000, 0x03ff2000, 0x87fffffe, 0x07fffffe, 0, 0, 0, 0};

//// Значения поля CLASS в секциях Answer, Authority и Additional
// enum DNS_CLASS { IN = 1, CS, CH, HS };

// Структура заголовка пакета DNS
typedef struct {
    const uint16_t id;
    const uint8_t rcode : 4;
    const uint8_t z : 3;
    const uint8_t ra : 1;
    const uint8_t rd : 1;
    const uint8_t tc : 1;
    const uint8_t aa : 1;
    const uint8_t opcode : 4;
    const uint8_t qr : 1;
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
    char mname[MAX_NAME_LENGTH];
    char rname[MAX_NAME_LENGTH];
} DNS_type_SOA;

// Структура секций Answer, Authority и Additional
#pragma pack(push, 1)
typedef struct {
    uint16_t type;
    uint16_t class_;
    uint32_t ttl;
    uint16_t rdlength;
    union {
        uint8_t rdata[MAX_NAME_LENGTH];
        DNS_type_SOA soa;
    };
    char answer_name[MAX_NAME_LENGTH];
} DNS_response;
#pragma pack(pop)

typedef struct {
    DNS_header header;
    DNS_response response[MAX_RESPONSE];
} DNS_packet;

/**
@brief Парсер меток для определения полей name, rdata
@param data - заполняемое поле, data_len - длина данных, offset - смещение,
@return offset - OK, -1 - Error
*/
int16_t dns_parse_label(const uint8_t* data, uint16_t data_len, int16_t offset) {
    // Если первые два бита равны 00 - обычная метка, следующие 6 бит определяют длину метки
    if((data[offset] & 0xc0u) == 0x00) {
        while(data[offset] && ((data[offset] & 0xc0u) != 0xc0u)) {
            if(offset++ > data_len)
                return -1;
        }
    }
    if((data[offset] & 0xc0u) == 0xc0u) {
        offset += 2;
    }
    else
        return -1;
    return offset;
}

///**
//@brief Проверка корректности метки
//@param data  - данные метки
//@return 0 - OK, -1 - Error
// */
//int dns_check_label(char* data) {
//    if(!*data)
//        return -1;
//    char letter = *data;
//    if(!((letter >= 'A' && letter <= 'Z') || (letter >= 'a' && letter <= 'z')))
//        return -1;
//    while((letter = *(++data))) {
//        if(!(letter == '-' || (letter >= 'A' && letter <= 'Z') || (letter >= 'a' && letter <= 'z') ||
//             ((letter >= '0' && letter <= '9')) || letter == '.'))
//            return -1;
//    }
//
//    return 0;
//}

/**
@brief Парсер секций Answer, Authority и Additional
@param data - данные пакета, data_len - длина данных, ip - поле rdata, ip_type - версия протокола IP,
       offset - смещение от начала пакета
@return offset - OK, -1 - Error
*/
int16_t dns_parse_answer(const uint8_t* data, uint16_t data_len, uint8_t* ip, uint8_t* ip_type, int16_t offset) {
    uint16_t field = 0;
    offset         = dns_parse_label(data, data_len, offset);
    if(offset == -1)
        return -1;
    int16_t k = offset;
    DNS_response response;
    // Значения полей структуры Response, кроме поля name
    for(; offset < k + 10; offset += 2) {
        field = data[offset + 1];
        field += (data[offset] << 8u);
        memcpy(&((uint8_t*) (&response))[offset - k], &field, 2);
    }
    response.ttl = ((response.ttl << 16u) & 0xffff0000u) | ((response.ttl >> 16u) & 0x0000ffffu);
    if(response.rdlength + offset > data_len)
        return -1;
    switch(response.type) {
        case A:
            if(response.rdlength != 4)
                response.rdlength = 4;
            *ip_type = AF_INET;
            memcpy(ip, &data[offset], response.rdlength);
            break;
        case AAAA:
            if(response.rdlength != 16)
                response.rdlength = 16;
            *ip_type = AF_INET6;
            memcpy(ip, &data[offset], response.rdlength);
            break;
        default:
            break;
    }
    offset += response.rdlength;
    return offset;
}

uint8_t dns_handle(const unsigned char* data, uint16_t data_len, DNS* dns) {

    uint16_t field              = 0;
    const uint8_t header_length = sizeof(DNS_header);
    int16_t offset              = header_length;
    DNS_header dns_header;
    // Header
    for(int i = 0; i < header_length; i += 2) {
        field = data[i + 1];
        field += (data[i] << 8u);
        memcpy(&((uint8_t*) &dns_header)[i], &field, 2);
    }
    if(!dns_header.qr || dns_header.rcode)
        return 1;
    // После секции Header следует секция Question (e.g. mozilla.org),
    // необходимо дойти до секции Answer
    // В 13 байте (начале секции Question) пакета указана длина первой части секции Question
    // e.g. mozilla
    // Двигаемся до конца секции Question
    int8_t k = 0;
    // Проверка на валидность символов из библиотеки NDPI
    while(data[offset]) {
        uint8_t c, cl = data[offset++];

        if((cl & 0xc0u) != 0 ||  // we not support compressed names in query
           offset + cl >= data_len) {
            return 1;
        }
        if(k && k < data_len)
            dns->name[k++] = '.';
        while(data[offset] && cl > 0) {
            uint32_t shift;
            c     = data[offset++];
            shift = ((uint32_t) 1) << (c & 0x1fu);
            if(!(dns_validchar[c >> 5u] & shift))
                return 1;
            dns->name[k++] = (char) tolower(c);
            cl--;
        }
    }
    dns->name[k] = 0;
    // Пропускаем поля qtype и qclass секции Question
    offset += 5;
    // Секции Answer, Authority и Additional
    uint16_t count = dns_header.ancount + dns_header.nscount + dns_header.arcount;
    if(count > MAX_RESPONSE)
        count = MAX_RESPONSE;
    for(int i = 0; i < count; i++) {
        offset = dns_parse_answer(data, data_len, dns->ip[i], &dns->ip_type[i], offset);
        // Проверка корректности поля Name
        // Если некорректно обработан ответ
        if(offset == -1) {
            return 1;
        }
        if(!(*dns->ip[i])) {
            i--;
            count--;
        }
    }
    return 0;
}