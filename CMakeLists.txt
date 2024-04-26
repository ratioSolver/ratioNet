cmake_minimum_required(VERSION 3.5.0)
project(ratioNet VERSION 0.2.0 LANGUAGES CXX)
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fsanitize=undefined")

include(CTest)
enable_testing()

find_package(Boost REQUIRED COMPONENTS system)

if(NOT TARGET json)
    add_subdirectory(extern/json)
endif()

option(USE_SSL "Use Secure Sockets Layer (SSL) for secure communication" OFF)
set(SERVER_HOST "0.0.0.0" CACHE STRING "The address the server listens on")
set(SERVER_PORT "8080" CACHE STRING "The port the server listens on")

message(STATUS "Use SSL: ${USE_SSL}")
message(STATUS "Server address: ${SERVER_HOST}")
message(STATUS "Server port: ${SERVER_PORT}")

if(USE_SSL)
    find_package(OpenSSL REQUIRED)

    set(TLS_VERSIONS tlsv11 tlsv12 tlsv13)
    set(TLS_VERSION tlsv12 CACHE STRING "Specify the desired TLS version")
    set_property(CACHE TLS_VERSION PROPERTY STRINGS ${TLS_VERSIONS})
    if(NOT TLS_VERSION IN_LIST TLS_VERSIONS)
        message(FATAL_ERROR "Invalid TLS version specified")
    endif()
    message(STATUS "TLS version: ${TLS_VERSION}")
endif()

add_library(ratioNet src/server.cpp src/session.cpp src/ws_session.cpp src/client.cpp src/ws_client.cpp)
target_link_libraries(ratioNet PUBLIC Boost::system json)
target_include_directories(ratioNet PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)
target_compile_definitions(ratioNet PUBLIC SERVER_HOST="${SERVER_HOST}" SERVER_PORT=${SERVER_PORT})

if (USE_SSL)
    target_link_libraries(ratioNet PUBLIC OpenSSL::SSL OpenSSL::Crypto)
    target_compile_definitions(ratioNet PRIVATE USE_SSL TLS_VERSION=${TLS_VERSION})
endif()

if(BUILD_TESTING)
    add_subdirectory(tests)
endif()

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)