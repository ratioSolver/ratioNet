cmake_minimum_required(VERSION 3.5.0)
project(ratioNet VERSION 0.2.0 LANGUAGES CXX)

include(CTest)
enable_testing()

find_package(Boost REQUIRED COMPONENTS system)

option(USE_SSL "Use Secure Sockets Layer (SSL) for secure communication" ON)
set(SERVER_ADDRESS "0.0.0.0" CACHE STRING "The address the server listens on")
set(SERVER_PORT "8080" CACHE STRING "The port the server listens on")

message(STATUS "Use SSL:                ${USE_SSL}")
message(STATUS "Server address:         ${SERVER_ADDRESS}")
message(STATUS "Server port:            ${SERVER_PORT}")

if(USE_SSL)
    find_package(OpenSSL REQUIRED)

    set(TLS_VERSIONS tlsv11 tlsv12 tlsv13)
    set(TLS_VERSION tlsv12 CACHE STRING "Specify the desired TLS version")
    set_property(CACHE TLS_VERSION PROPERTY STRINGS ${TLS_VERSIONS})
    if(NOT TLS_VERSION IN_LIST TLS_VERSIONS)
        message(FATAL_ERROR "Invalid TLS version specified")
    endif()
    message(STATUS "TLS version:            ${TLS_VERSION}")
endif()

add_library(ratioNet src/server.cpp)
target_compile_features(ratioNet PUBLIC cxx_std_17)
target_include_directories(ratioNet PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>/include)
target_link_libraries(ratioNet PUBLIC Boost::system)
target_compile_definitions(ratioNet PUBLIC SERVER_ADDRESS="${SERVER_ADDRESS}" SERVER_PORT="${SERVER_PORT}")

if (USE_SSL)
    target_link_libraries(ratioNet PUBLIC OpenSSL::SSL OpenSSL::Crypto)
    target_compile_definitions(ratioNet PUBLIC USE_SSL TLS_VERSION=${TLS_VERSION})
endif()

if(BUILD_TESTING)
    add_subdirectory(tests)
endif()

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)