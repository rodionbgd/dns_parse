#include "dns_parser.h"
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

/**
@brief Парсер меток для определения полей name, rdata
@param data - заполняемое поле, offset - смещение, quest_name - поле QNAME секции Question, packet - пакет
@return offset - OK, -1 - Error
*/
int16_t
dns_parse_label(char *data, int16_t offset, uint16_t dns_length, char *quest_name, const unsigned char *packet) {

    u_int16_t cur_name_length = 0;
    uint8_t answer_name_length = strlen(quest_name) + 1;
    const uint8_t header_length = 12;
    uint16_t field;
    int16_t tmp_offset = offset;

    while (packet[tmp_offset]) {
        field = packet[tmp_offset + 1];
        field += (packet[tmp_offset] << 8u);
        // Если первые два бита равны 00 - обычная метка, следующие 6 бит определяют длину метки
        if ((packet[tmp_offset] & 0xc0u) == 0x00) {
            // Определяем значение поля name, часто совпадает с таким же полем в секции Answer
            if (packet[tmp_offset] + offset > dns_length)
                return -1;
            memcpy(data + cur_name_length, &packet[tmp_offset + 1], packet[tmp_offset]);
            cur_name_length += packet[tmp_offset];
            data[cur_name_length++] = '.';
            tmp_offset += packet[tmp_offset] + 1;
            offset = tmp_offset;
            // Если метка c0, но содержит частично quest_name или выходит за его пределы
        } else if (field != 0xc00c) {
            uint16_t label_offset = (field & 0x3fffu);
            if (label_offset > dns_length)
                return -1;
            // Если метка выходит за пределы quest_name, собираем data
            if (label_offset > header_length + answer_name_length) {
                uint16_t i = label_offset;
                while (packet[i]) {
                    if ((packet[i] & 0xc0u)) {
                        label_offset = packet[i + 1] + (packet[i] << 8u);
                        label_offset &= 0x3fffu;
                        i = label_offset;

                    }
                    if (i > dns_length || packet[i] + offset > dns_length)
                        return -1;
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
    if (offset > dns_length)
        offset = -1;
    return offset;
}

/**
@brief Проверка корректности метки
@param data  - данные метки
@return 0 - OK, -1 - Error
 */
int dns_check_label(char *data) {
    if (!*data)
        return -1;
    char letter;
    while ((letter = *data++)) {
        if (!(letter == '-' || (letter >= 'A' && letter <= 'Z') || (letter >= 'a' && letter <= 'z') ||
              ((letter >= '0' && letter <= '9')) || letter == '.' || letter == ':'))
            return -1;
    }

    return 0;
}

/**
@brief Парсер секций Answer, Authority и Additional
@param response - одна из трех секций, offset - смещение, quest_name - поле QNAME секции Question, packet - пакет
@return offset - OK, -1 - Error
*/
int16_t dns_parse_answer(DNS_response *response, int16_t offset, uint16_t dns_length, char *quest_name,
                         const unsigned char *packet) {
    uint16_t field = 0;
    int16_t tmp_offset;
    offset = dns_parse_label(response->answer_name, offset, dns_length, quest_name, packet);
    if (offset == -1)
        return -1;
    int16_t k = offset;

    // Значения полей структуры Response, кроме поля name
    for (; offset < k + 10; offset += 2) {
        field = packet[offset + 1];
        field += (packet[offset] << 8u);
        memcpy(((uint8_t *) response) + offset - k, &field, 2);
    }
    response->ttl = ((response->ttl << 16u) & 0xffff0000u) | ((response->ttl >> 16u) & 0x0000ffffu);
    if (response->rdlength + offset > dns_length)
        return -1;

    // Union для определения ip в типах: A, AAAA
    union {
        struct in_addr ipv4;
        struct in6_addr ipv6;
        struct {
            uint8_t byte[16];
        };
    } ip;

    tmp_offset = offset;
    switch (response->type) {
        case A :
            if (response->rdlength != 4)
                response->rdlength = 4;
            for (int i = 0; i < response->rdlength; i++) {
                ip.byte[i] = packet[offset + i];
            }
            inet_ntop(AF_INET, &(ip.ipv4), response->rdata, INET_ADDRSTRLEN);
            break;
        case AAAA:
            if (response->rdlength != 16)
                response->rdlength = 16;
            for (int i = 0; i < response->rdlength; i++) {
                ip.byte[i] = packet[offset + i];
            }
            inet_ntop(AF_INET6, &(ip.ipv6), response->rdata, INET6_ADDRSTRLEN);
            break;
//      case TXT:
//      case NS:
        case CNAME:
        case PTR:
        case MX:
            if (response->type == MX) // Пропущено поле preference
            {
                tmp_offset = offset + 2;
            }
            tmp_offset = dns_parse_label((char *) response->rdata, tmp_offset, dns_length, quest_name, packet);
            if (tmp_offset == -1)
                response->rdata[0] = '\0';
            break;
        case SOA: {
            // Тип SOA содержит: имя сервера-источника, e-mail и служебные данные
            //имя сервера-источника
            tmp_offset = dns_parse_label((char *) response->soa.mname, offset, dns_length, quest_name, packet);
            if (tmp_offset == -1)
                response->soa.mname[0] = '\0';
            // e-mail
            tmp_offset = dns_parse_label((char *) response->soa.rname, tmp_offset, dns_length, quest_name, packet);
            if (tmp_offset == -1)
                response->soa.rname[0] = '\0';
            break;
        }
// To be continued...
//        case MD:
//        case MF:
//        case MB:
//        case MG:
//        case MR:
//        case NULL_:
//        case WKS:
//        case HINFO:
//        case MINFO:
        default:
            break;
    }
    offset += response->rdlength;
    return offset;
}

DNS *dns_handle(const unsigned char *packet, uint16_t dns_length, DNS *dns) {

    uint16_t field = 0;
    const uint8_t header_length = 12;
    int16_t offset = header_length;
    char quest_name[MAX_NAME_LENGTH];

    // Header
    for (int i = 0; i < header_length; i += 2) {
        field = packet[i + 1];
        field += (packet[i] << 8u);
        memcpy(((uint8_t *) &dns->header) + i, &field, 2);
    }
    if (!dns->header.qr || dns->header.rcode)
        return NULL;
    // После секции Header следует секция Question (e.g. mozilla.org),
    // необходимо дойти до секции Answer
    // В 13 байте (начале секции Question) пакета указана длина первой части секции Question
    // e.g. mozilla
    // Двигаемся до конца секции Question
    while (packet[offset]) {
        // Определяем значение поля name, часто совпадает с таким же полем в секции Answer
        // Если метка некорректная или длина метки выходит за пределы пакета
        if (((packet[offset] & 0xc0u) != 0xc0 && (packet[offset] & 0xc0u) != 0x00) ||
            (packet[offset] & 0x3fu + offset) > dns_length || offset - header_length > dns_length)
            return NULL;
        memcpy(quest_name + offset - header_length, &packet[offset + 1], packet[offset]);
        quest_name[packet[offset] + offset - header_length] = '.';
        offset += packet[offset] + 1;
    }
    quest_name[offset - header_length - 1] = 0;
    // Если некорректные символы в запросе
    if (dns_check_label(quest_name))
        return NULL;
    // Пропускаем поля qtype и qclass секции Question
    offset += 5;
    // Секции Answer, Authority и Additional
    uint16_t count = dns->header.ancount + dns->header.nscount + dns->header.arcount;
    if (count > MAX_RESPONSE)
        count = MAX_RESPONSE;
    for (int i = 0; i < count; i++) {
        offset = dns_parse_answer(dns->response + i, offset, dns_length, quest_name, packet);
        // Проверка корректности поля Name
        // Если некорректно обработан ответ
        if (offset == -1) {
            dns->response[i].rdata[0] = '\0';
            return dns;
        }
        if (dns_check_label(dns->response[i].rdata)) {
            dns->response[i].rdata[0] = '\0';
            i--;
            count--;
        }
    }
    return dns;
}