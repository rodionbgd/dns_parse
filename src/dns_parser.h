#ifndef DNS_PARSER_LIBRARY_H
#define DNS_PARSER_LIBRARY_H

#include <time.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_NAME_LENGTH 256
#define MAX_RESPONSE    12
#define MAX_IP_LENGTH   16

typedef struct {
    char name[MAX_NAME_LENGTH];
    uint8_t ip[MAX_RESPONSE][MAX_IP_LENGTH];
    uint8_t ip_type[MAX_IP_LENGTH];
} DNS;

/**
@brief Обработка пакета DNS
@param packet - пакет DNS, dns_length - длина пакета DNS, dns - структура данных пакета DNS
return 0 - OK, 1 - Error
*/
uint8_t dns_handle(const unsigned char* packet, uint16_t dns_length, DNS* dns);

#ifdef __cplusplus
}
#endif
#endif  // DNS_PARSER_LIBRARY_H
