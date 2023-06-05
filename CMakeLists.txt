cmake_minimum_required(VERSION 3.10)
project(MyProject C)

set(CMAKE_BINARY_DIR ${CMAKE_SOURCE_DIR}/build)
set(EXECUTABLE_OUTPUT_PATH ${CMAKE_SOURCE_DIR}/bin)
set(BENCHMARK_OUTPUT_PATH ${CMAKE_SOURCE_DIR}/benchmark)
set(LIBRARY_OUTPUT_PATH ${CMAKE_BINARY_DIR})
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")

include_directories(libs)

file(GLOB LIBRARY_SOURCES libs/*.c)
file(GLOB LIBRARY_HEADERS libs/*.h)
file(GLOB ELGAMAL_MOD src/elgamal-mod*)

add_library(mdr ${LIBRARY_SOURCES} ${LIBRARY_HEADERS})

add_library(elgamal-mod ${ELGAMAL_MOD})
add_library(anon-proxy src/anon-proxy.c src/anon-proxy.h)

add_executable(main-elgamal-mod src/main-elgamal-mod.c)
add_executable(bench-elgamal-mod src/bench-elgamal-mod.c)

add_executable(main-anon-proxy src/main-anon-proxy.c)


# set output directory of executable
set_target_properties(
        main-elgamal-mod
        PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${EXECUTABLE_OUTPUT_PATH}"
)

set_target_properties(
        bench-elgamal-mod
        PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${BENCHMARK_OUTPUT_PATH}"
)

target_link_libraries(main-elgamal-mod mdr elgamal-mod m gmp nettle)
target_link_libraries(bench-elgamal-mod mdr elgamal-mod m gmp nettle)

target_link_libraries(main-anon-proxy mdr anon-proxy m gmp nettle)