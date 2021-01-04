cmake_minimum_required(VERSION 3.17)
project(ICMP)

set(CMAKE_CXX_STANDARD 14)

add_executable(ICMP icmp.cpp)
add_executable(ICMP2 icmp2.c)
add_executable(ICMP3 myping.cpp)
add_executable(TheirPing myNuPing.c)