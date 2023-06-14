cmake_minimum_required(VERSION 3.10)
project(MyProject C)

set(CMAKE_BINARY_DIR ${CMAKE_SOURCE_DIR}/build)
set(EXECUTABLE_OUTPUT_PATH ${CMAKE_SOURCE_DIR}/bin)
set(BENCHMARK_OUTPUT_PATH ${CMAKE_SOURCE_DIR}/bin)
set(TEST_OUTPUT_PATH ${CMAKE_SOURCE_DIR}/bin)
set(LIBRARY_OUTPUT_PATH ${CMAKE_BINARY_DIR})
set(CMAKE_C_STANDARD 99)

set(CMAKE_STATIC_LIBRARY_PREFIX "lib-")
set(CMAKE_SHARED_LIBRARY_PREFIX "lib-")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")

include_directories(libs-mdr src)

file(GLOB MDR_LIBRARIES_SOURCES libs-mdr/*.c)
file(GLOB MDR_LIBRARIES_HEADERS libs-mdr/*.h)

add_library(mdr ${MDR_LIBRARIES_SOURCES} ${MDR_LIBRARIES_HEADERS})

add_library(elgamal-mod src/lib-elgamal-mod.c src/lib-elgamal-mod.h)
add_library(anon-proxy src/lib-anon-proxy.c src/lib-anon-proxy.h)

add_executable(main-elgamal-mod examples/main-elgamal-mod.c)
add_executable(bench-elgamal-mod benchmark/bench-elgamal-mod.c)
add_executable(test-elgamal-mod test/test-elgamal-mod.c)

add_executable(main-anon-proxy examples/main-anon-proxy.c)


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

set_target_properties(
        test-elgamal-mod
        PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${TEST_OUTPUT_PATH}"
)

target_link_libraries(main-elgamal-mod mdr elgamal-mod m gmp nettle)
target_link_libraries(bench-elgamal-mod mdr elgamal-mod m gmp nettle)
target_link_libraries(test-elgamal-mod mdr elgamal-mod m gmp nettle)

target_link_libraries(main-anon-proxy mdr anon-proxy m gmp nettle)