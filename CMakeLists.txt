cmake_minimum_required (VERSION 3.0)
project (zleptjson_test C)

if (CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ansi -pedantic -Wall")
endif()

add_library(zleptjson zleptjson.c)

set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)
add_executable(zleptjson_test test.c)

target_link_libraries(zleptjson_test zleptjson)