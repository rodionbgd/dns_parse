#define CATCH_CONFIG_MAIN

#include "catch.hpp"

#include <cstdint>
#include <cstring>
#include "dns_parser.h"

uint8_t packet[2][512] = {{0x9f, 0x85, 0x81, 0x80, 0x00, 0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x0e, 0x64, 0x32, 0x6e, 0x78, 0x71, 0x32, 0x75, 0x61, 0x70, 0x38, 0x38, 0x75, 0x73, 0x6b, 0x0a, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x66, 0x72, 0x6f, 0x6e, 0x74, 0x03, 0x6e, 0x65, 0x74, 0x00, 0x00, 0x1c, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x25, 0x00, 0x10, 0x26, 0x00, 0x90, 0x00, 0x21, 0x18, 0xba, 0x00, 0x00, 0x0a, 0xda, 0x5e, 0x79, 0x00, 0x93, 0xa1, 0xc0, 0x0c, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x25, 0x00, 0x10, 0x26, 0x00, 0x90, 0x00, 0x21, 0x18, 0x12, 0x00, 0x00, 0x0a, 0xda, 0x5e, 0x79, 0x00, 0x93, 0xa1, 0xc0, 0x0c, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x25, 0x00, 0x10, 0x26, 0x00, 0x90, 0x00, 0x21, 0x18, 0x24, 0x00, 0x00, 0x0a, 0xda, 0x5e, 0x79, 0x00, 0x93, 0xa1, 0xc0, 0x0c, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x25, 0x00, 0x10, 0x26, 0x00, 0x90, 0x00, 0x21, 0x18, 0xaa, 0x00, 0x00, 0x0a, 0xda, 0x5e, 0x79, 0x00, 0x93, 0xa1, 0xc0, 0x0c, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x25, 0x00, 0x10, 0x26, 0x00, 0x90, 0x00, 0x21, 0x18, 0xf4, 0x00, 0x00, 0x0a, 0xda, 0x5e, 0x79, 0x00, 0x93, 0xa1, 0xc0, 0x0c, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x25, 0x00, 0x10, 0x26, 0x00, 0x90, 0x00, 0x21, 0x18, 0x44, 0x00, 0x00, 0x0a, 0xda, 0x5e, 0x79, 0x00, 0x93, 0xa1, 0xc0, 0x0c, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x25, 0x00, 0x10, 0x26, 0x00, 0x90, 0x00, 0x21, 0x18, 0x1a, 0x00, 0x00, 0x0a, 0xda, 0x5e, 0x79, 0x00, 0x93, 0xa1, 0xc0, 0x0c, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x25, 0x00, 0x10, 0x26, 0x00, 0x90, 0x00, 0x21, 0x18, 0xbe, 0x00, 0x00, 0x0a, 0xda, 0x5e, 0x79, 0x00, 0x93, 0xa1},
                          {0x66, 0xa0, 0x81, 0x80, 0x00, 0x01, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x08, 0x73, 0x6e, 0x69, 0x70, 0x70, 0x65, 0x74, 0x73, 0x03, 0x63, 0x64, 0x6e, 0x07, 0x6d, 0x6f, 0x7a, 0x69, 0x6c, 0x6c, 0x61, 0x03, 0x6e, 0x65, 0x74, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x19, 0x00, 0x1c, 0x0e, 0x64, 0x32, 0x32, 0x38, 0x7a, 0x39, 0x31, 0x61, 0x75, 0x31, 0x31, 0x75, 0x6b, 0x6a, 0x0a, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x66, 0x72, 0x6f, 0x6e, 0x74, 0xc0, 0x21, 0xc0, 0x36, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x13, 0x00, 0x04, 0x34, 0x55, 0x2f, 0x34, 0xc0, 0x36, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x13, 0x00, 0x04, 0x34, 0x55, 0x2f, 0x4d, 0xc0, 0x36, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x13, 0x00, 0x04, 0x34, 0x55, 0x2f, 0x78, 0xc0, 0x36, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x13, 0x00, 0x04, 0x34, 0x55, 0x2f, 0x52},
};

uint16_t dns_length[] = {271,146};

TEST_CASE("Секция Header", "[dns_handle]") {
    DNS dns = {};
    dns_handle(packet[0], dns_length[0], &dns);
    REQUIRE(dns.header.id == 0x9f85);
    REQUIRE(dns.header.qr == 1);
    REQUIRE(dns.header.qdcount == 1);
    REQUIRE(dns.header.ancount == 8);
    REQUIRE(dns.header.nscount == 0);
    REQUIRE(dns.header.arcount == 0);

    dns_handle(packet[1], dns_length[1], &dns);
    REQUIRE(dns.header.id == 0x66a0);
    REQUIRE(dns.header.qr == 1);
    REQUIRE(dns.header.qdcount == 1);
    REQUIRE(dns.header.ancount == 5);
    REQUIRE(dns.header.nscount == 0);
    REQUIRE(dns.header.arcount == 0);
}

TEST_CASE("Поле answer_name секций Answer, Authority и Additional", "[dns_handle]") {
    DNS dns={};
    dns_handle(packet[0],dns_length[0],&dns);
    for (int i = 0; i < dns.header.ancount + dns.header.nscount + dns.header.arcount; i++) {
        REQUIRE(strcmp(dns.response[i].answer_name, "d2nxq2uap88usk.cloudfront.net") == 0);
    }
    dns_handle(packet[1],dns_length[1],&dns);
    REQUIRE(strcmp(dns.response[0].answer_name, "snippets.cdn.mozilla.net") == 0);
    for (int i = 1; i < dns.header.ancount + dns.header.nscount + dns.header.arcount; i++) {
        REQUIRE(strcmp(dns.response[i].answer_name, "d228z91au11ukj.cloudfront.net") == 0);
    }
}

TEST_CASE("Тип AAAA поля rdata секций Answer, Authority и Additional", "[dns_handle]") {
    DNS dns={};
    dns_handle(packet[0],271,&dns);
    REQUIRE(strcmp(dns.response[0].rdata, "2600:9000:2118:ba00:a:da5e:7900:93a1") == 0);
    REQUIRE(strcmp(dns.response[2].rdata, "2600:9000:2118:2400:a:da5e:7900:93a1") == 0);
}

TEST_CASE("Тип A поля rdata секций Answer, Authority и Additional", "[dns_handle]") {
    DNS dns={};
    dns_handle(packet[1],dns_length[1],&dns);
    REQUIRE(strcmp(dns.response[1].rdata, "52.85.47.52") == 0);
    REQUIRE(strcmp(dns.response[2].rdata, "52.85.47.77") == 0);
    REQUIRE(strcmp(dns.response[3].rdata, "52.85.47.120") == 0);
    REQUIRE(strcmp(dns.response[4].rdata, "52.85.47.82") == 0);
}

TEST_CASE("Тип CNAME поля rdata секций Answer, Authority и Additional", "[dns_handle]") {
    DNS dns={};
    dns_handle(packet[1],dns_length[1],&dns);
    REQUIRE(strcmp(dns.response[0].rdata, "d228z91au11ukj.cloudfront.net") == 0);
}
