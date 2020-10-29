cmake_minimum_required(VERSION 3.14)
project(dns_parser)

set(SOURCE_FILES dns_parser.c
        dns_parser.h)

add_library(${PROJECT_NAME} STATIC ${SOURCE_FILES})