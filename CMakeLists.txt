cmake_minimum_required(VERSION 3.14)
project(dns C)

set(CMAKE_C_STANDARD 11)

set(SOURCE_FILES src/dns_parser.c
        src/dns_parser.h)
add_library(dns_parse STATIC ${SOURCE_FILES})

add_subdirectory(test)

#add_executable(${PROJECT_NAME} main.c)
#target_link_libraries(${PROJECT_NAME} dns_parse pcap)