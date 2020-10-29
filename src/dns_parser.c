#include "dns_parser.h"
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

/**
@brief Парсер меток для определения полей name, rdata
@param data - заполняемое поле, offset - смещение, quest_name - поле QNAME секции Question, packet - пакет
@return offset
*/
uint16_t dns_parse_label(char *data, uint16_t offset, char *quest_name, const unsigned char *packet) {
    u_int16_t cur_name_length = 0;

    uint8_t answer_name_length = strlen(quest_name) + 1;
    const uint8_t header_length = 12;
    uint16_t field = 0;
    uint16_t tmp_offset = offset;

    while (packet[tmp_offset]) {
        field = packet[tmp_offset + 1];
        field += (packet[tmp_offset] << 8u);
        // Если первые два бита равны 00 - обычная метка, следующие 6 бит определяют длину метки
        if (!(packet[tmp_offset] & 0xc0u)) {
            // Определяем значение поля name, часто совпадает с таким же полем в секции Answer
            memcpy(data + cur_name_length, &packet[tmp_offset + 1], packet[tmp_offset]);
            cur_name_length += packet[tmp_offset];
            data[cur_name_length++] = '.';
            tmp_offset += packet[tmp_offset] + 1;
            offset = tmp_offset;
            // Если метка c0, но содержит частично quest_name или выходит за его пределы
        } else if (field != 0xc00c) {
            uint16_t label_offset = (field & 0x3fffu);
            // Если метка выходит за пределы quest_name, собираем data
            if (label_offset > header_length + answer_name_length) {
                uint16_t i = label_offset;
                while (packet[i]) {
                    if ((packet[i] & 0xc0u)) {
                        label_offset = packet[i + 1] + (packet[i] << 8u);
                        label_offset &= 0x3fffu;
                        i = label_offset;
                    }
                    memcpy(data + cur_name_length, &packet[i + 1], packet[i]);
                    cur_name_length += packet[i];
                    data[cur_name_length++] = '.';
                    i += packet[i] + 1;
                }
            }
                // Если метка ссылается на часть quest_name
            else {
                memcpy(data + cur_name_length, &quest_name[label_offset - header_length],
                       answer_name_length - label_offset + header_length);
                cur_name_length += answer_name_length - label_offset + header_length;

            }
            tmp_offset += 2;
            break;
        }
            // Если метка содержит полный quest_name
        else {
            memcpy(data + cur_name_length, quest_name, answer_name_length);
            cur_name_length += answer_name_length;
            break;
        }
    }
    data[cur_name_length - 1] = 0;
    // Если не было метки 0xc0
    if (!packet[offset]) {
        offset++;
    } else if (tmp_offset <= offset) {
        offset += 2;
    } else {
        offset = tmp_offset;
    }
    return offset;
}

/**
@brief Проверка корректности метки
@param data  - данные метки
@return 0 - OK, -1 - Error
 */
int dns_check_label(char *data) {
    if (!data)
        return -1;
    char letter = *data++;
    if (!((letter >= 'A' && letter <= 'Z') || (letter >= 'a' && letter <= 'z')))
        return -1;
    while ((letter = *data++)) {
        if (!(letter == '-' || (letter >= 'A' && letter <= 'Z') || (letter >= 'a' && letter <= 'z') ||
              ((letter >= '0' && letter <= '9')) || letter == '.'))
            return -1;
    }

    return 0;
}

/**
@brief Парсер секций Answer, Authority и Additional
@param response - одна из трех секций, offset - смещение, quest_name - поле QNAME секции Question, packet - пакет
@return offset
*/
uint16_t dns_parse_answer(DNS_response *response, uint16_t offset, char *quest_name, const unsigned char *packet) {
    uint16_t field = 0;
    uint16_t tmp_offset;
    offset = dns_parse_label(response->answer_name, offset, quest_name, packet);
    uint16_t k = offset;

    // Значения полей структуры Response, кроме поля name
    for (; offset < k + 10; offset += 2) {
        field = packet[offset + 1];
        field += (packet[offset] << 8u);
        memcpy(((uint8_t *) response) + offset - k, &field, 2);
    }
    response->ttl = ((response->ttl << 16u) & 0xffff0000u) | ((response->ttl >> 16u) & 0x0000ffffu);

    // Union для определения ip в типах: A, AAAA
    union {
        struct in_addr ipv4;
        struct in6_addr ipv6;
        struct {
            uint8_t byte[16];
        };
    } ip;

    tmp_offset = offset;
    char wr_data[] = "Wrong data";
    switch (response->type) {
        case A :
            if (response->rdlength != 4)
                memcpy(response->rdata, wr_data, sizeof(wr_data));
            else {
                for (int i = 0; i < response->rdlength; i++) {
                    ip.byte[i] = packet[offset + i];
                }
                inet_ntop(AF_INET, &(ip.ipv4), response->rdata, INET_ADDRSTRLEN);
            }
            break;
        case AAAA:
            if (response->rdlength != 16)
                memcpy(response->rdata, wr_data, sizeof(wr_data));
            else {
                for (int i = 0; i < response->rdlength; i++) {
                    ip.byte[i] = packet[offset + i];
                }
                inet_ntop(AF_INET6, &(ip.ipv6), response->rdata, INET6_ADDRSTRLEN);
            }
            break;
        case MX:
        case CNAME:
        case PTR:
        case TXT:
        case NS:
            if (response->type == MX) // Пропущено поле preference
            {
                tmp_offset = offset + 2;
            }
            dns_parse_label((char *) response->rdata, tmp_offset, quest_name, packet);
            break;
        case SOA: {
            // Тип SOA содержит: имя сервера-источника, e-mail и служебные данные
            //имя сервера-источника
            tmp_offset = dns_parse_label((char *) response->soa.mname, offset, quest_name, packet);
            // e-mail
            tmp_offset = dns_parse_label((char *) response->soa.rname, tmp_offset, quest_name, packet);
            // служебные данные
            for (k = tmp_offset; k < tmp_offset + 20; k += 4) {
                uint32_t tmp_field =
                        (packet[k] << 24u) + (packet[k + 1] << 16u) + (packet[k + 2] << 8u) + packet[k + 3];
                memcpy((uint8_t *) &(response->soa) + k - tmp_offset, &tmp_field, 4);
            }
            break;
        }
            // To be continued...
        case MD:
        case MF:
        case MB:
        case MG:
        case MR:
        case NULL_:
        case WKS:
        case HINFO:
        case MINFO:
            break;

    }
    offset += response->rdlength;
    return offset;
}

DNS *dns_handle(const unsigned char *packet) {

    DNS_header header;
    uint16_t field = 0;
    const uint8_t header_length = 12;
    uint16_t offset = header_length;
    char quest_name[128]; //256

    // Header
    for (int i = 0; i < header_length; i += 2) {
        field = packet[i + 1];
        field += (packet[i] << 8u);
        memcpy(((uint8_t *) &header) + i, &field, 2);
    }
    if (!header.qr)
        return NULL;

    DNS *dns = (DNS *) malloc(sizeof(DNS));
    if (!dns)
        return NULL;
    // После секции Header следует секция Question (e.g. mozilla.org),
    // необходимо дойти до секции Answer
    // В 13 байте (начале секции Question) пакета указана длина первой части секции Question
    // e.g. mozilla
    // Двигаемся до конца секции Question
    while (packet[offset]) {
        // Определяем значение поля name, часто совпадает с таким же полем в секции Answer
        memcpy(quest_name + offset - header_length, &packet[offset + 1], packet[offset]);
        quest_name[packet[offset] + offset - header_length] = '.';
        offset += packet[offset] + 1;
    }
    quest_name[offset - header_length - 1] = 0;
    // Пропускаем поля qtype и qclass секции Question
    offset += 5;
    // Секции Answer, Authority и Additional
    memcpy(&dns->header, &header, sizeof(header));
    uint16_t count = header.ancount + header.nscount + header.arcount;
    dns->response = (DNS_response *) malloc(count * sizeof(DNS_response));
    if (!dns->response)
        return NULL;
    for (int i = 0; i < count; i++) {
        dns->response[i].answer_name = (char *) malloc(128);
        if (!dns->response[i].answer_name)
            return NULL;
        offset = dns_parse_answer(dns->response + i, offset, quest_name, packet);
        // Проверка корректности поля Name
        if (dns_check_label(dns->response[i].answer_name)) {
            free(dns->response[i].answer_name);
            i--;
            count--;
        }
    }
    return dns;
}

void dns_clean(DNS *dns) {
    if (!dns)
        return;
    if (!dns->response) {
        free(dns);
        dns = NULL;
        return;

    }
    uint16_t count = dns->header.ancount + dns->header.nscount + dns->header.arcount;
    for (int i = 0; i < count; i++) {
        if (dns->response[i].answer_name) {
            free(dns->response[i].answer_name);
            dns->response[i].answer_name = NULL;
        }
    }
    free(dns->response);
    dns->response = NULL;
    free(dns);
    dns = NULL;
}