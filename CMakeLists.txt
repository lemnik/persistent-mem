cmake_minimum_required(VERSION 3.22.1)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_EXTENSIONS OFF)

project(persistentmem)

include_directories(include/)

add_compile_options("-nostdlib")

add_library(persistentmem STATIC persistent_mem.c)

add_executable(example example/main.cpp)
add_executable(test test/smoke_tests.cpp)

target_link_libraries(example persistentmem)
target_link_libraries(test persistentmem)
