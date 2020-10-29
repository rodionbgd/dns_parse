cmake_minimum_required(VERSION 3.14)
project(dns C)

add_subdirectory(src)
option(ENABLE_TEST_DNS "DNS parse" ON)
if (ENABLE_TEST_DNS)
    add_subdirectory(test)
endif ()

#add_executable(${PROJECT_NAME} main.c)
#target_link_libraries(${PROJECT_NAME} dns_parser pcap)