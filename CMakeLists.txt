cmake_minimum_required(VERSION 3.17)
project(ICMP)

set(CMAKE_CXX_STANDARD 14)

add_executable(ICMP myping.cpp)
add_executable(Sniffer sniffer.cpp headers.h)
add_executable(Sniffer2 sniffer2.c headers.h)