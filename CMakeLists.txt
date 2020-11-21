cmake_minimum_required(VERSION 3.1)
project(dns C)

set(CMAKE_C_STANDARD 11)
option(ENABLE_TESTS_DNS   "Тестирование парсера DNS" OFF)

set(SOURCE_FILES src/dns_parser.c
        src/dns_parser.h)
add_library(dns_parse STATIC ${SOURCE_FILES})

if (ENABLE_TESTS_DNS)
    add_subdirectory(test)
else ()
    set(NUM_SITES 5 CACHE STRING "Кол-во выводимых сайтов")
    add_definitions(-DNUM_SITES=${NUM_SITES})
    add_executable(${PROJECT_NAME} main.c)
    target_link_libraries(${PROJECT_NAME} dns_parse pcap)
endif ()