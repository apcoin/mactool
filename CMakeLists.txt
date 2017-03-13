cmake_minimum_required(VERSION 2.6)

project(arp_get C)

set(src_arp_get
    arp_get.c
    main.c)
    
ADD_DEFINITIONS(-O2 -Wall --std=gnu99 -Wmissing-declarations)

add_executable(arg_get ${src_arp_get})
