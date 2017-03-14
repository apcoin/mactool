cmake_minimum_required(VERSION 2.6)

project(arp_get C)

set(src_arp_get
    arp_get.c
    http_client.c
    main.c)
    
set(libs 
    json-c
    event)
    
ADD_DEFINITIONS(-O2 -Wall --std=gnu99 -Wmissing-declarations)

add_executable(arp_get ${src_arp_get})
target_link_libraries(arp_get ${libs})
