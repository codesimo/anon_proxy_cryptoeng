cmake_minimum_required(VERSION 3.10)
project(MyProject C)

set(CMAKE_BINARY_DIR ${CMAKE_SOURCE_DIR}/build)
set(EXECUTABLE_OUTPUT_PATH ${CMAKE_SOURCE_DIR}/bin)
set(BENCHMARK_OUTPUT_PATH ${CMAKE_SOURCE_DIR}/benchmark)
set(LIBRARY_OUTPUT_PATH ${CMAKE_BINARY_DIR})

include_directories(libs)

file(GLOB LIBRARY_SOURCES libs/*.c)
file(GLOB LIBRARY_HEADERS libs/*.h)
file(GLOB ELGAMAL_MOD src/elgamal-mod*)

add_library(libs ${LIBRARY_SOURCES} ${LIBRARY_HEADERS} ${ELGAMAL_MOD}  )

add_executable(main-elgamal-mod src/main-elgamal-mod.c)
add_executable(bench-elgamal-mod src/bench-elgamal-mod.c)
add_executable(anon-proxy src/anon-proxy.c)

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

target_link_libraries(main-elgamal-mod libs m gmp nettle)
target_link_libraries(bench-elgamal-mod libs m gmp nettle)
target_link_libraries(anon-proxy libs m gmp nettle)