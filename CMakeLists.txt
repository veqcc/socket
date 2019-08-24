cmake_minimum_required(VERSION 3.13)
project(socket)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pthread")

add_executable(socket
        main.c
        param.h
        param.c
        sock.h
        sock.c
        ether.h
        ether.c
        arp.h
        arp.c
        ip.h
        ip.c
        icmp.h
        icmp.c
        cmd.h
        cmd.c
        )
