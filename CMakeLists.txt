cmake_minimum_required(VERSION 2.6)

project(arp_get C)

set(src_arp_get
    arp_get.c
    main.c)
    
set(libs 
    ssl
	crypto
    event
    event_openssl)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -I/usr/local/include -L/usr/local/lib")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -I/usr/local/include")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -L/usr/local/lib")
    
ADD_DEFINITIONS(-O2 -Wall --std=gnu99 -Wmissing-declarations)

add_executable(arp_get ${src_arp_get})
target_link_libraries(arp_get ${libs})
