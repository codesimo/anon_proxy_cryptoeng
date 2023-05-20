cmake_minimum_required(VERSION 3.10)
project(MyProject C)

set(CMAKE_BINARY_DIR ${CMAKE_SOURCE_DIR}/build)
set(EXECUTABLE_OUTPUT_PATH ${CMAKE_SOURCE_DIR}/bin)
set(LIBRARY_OUTPUT_PATH ${CMAKE_BINARY_DIR})

include_directories(lib)

file(GLOB LIBRARY_SOURCES lib/*.c)
file(GLOB LIBRARY_HEADERS lib/*.h)
file(GLOB ELGAMAL_MOD src/elgamal-mod*)

add_library(libs ${LIBRARY_SOURCES} ${LIBRARY_HEADERS} ${ELGAMAL_MOD})

add_executable(anon-proxy src/anon-proxy.c)

# set output directory of executable
set_target_properties(
        anon-proxy
        PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${EXECUTABLE_OUTPUT_PATH}/elgamal-mod/"
)

target_link_libraries(anon-proxy libs m gmp nettle)