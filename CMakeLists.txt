cmake_minimum_required(VERSION 3.5.0)
project(ratioNet VERSION 0.2.0 LANGUAGES CXX)

include(CTest)
enable_testing()

find_package(Boost REQUIRED COMPONENTS system)
find_package(OpenSSL REQUIRED)

set(TLS_VERSIONS tlsv11 tlsv12 tlsv13)
set(TLS_VERSION tlsv12 CACHE STRING "Specify the desired TLS version")
set_property(CACHE TLS_VERSION PROPERTY STRINGS ${TLS_VERSIONS})

add_library(ratioNet INTERFACE)
target_compile_features(ratioNet INTERFACE cxx_std_17)
target_include_directories(ratioNet INTERFACE $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>/include)
target_link_libraries(ratioNet INTERFACE Boost::system OpenSSL::SSL OpenSSL::Crypto)
target_compile_definitions(ratioNet INTERFACE TLS_VERSION=${TLS_VERSION})

if(BUILD_TESTING)
    add_subdirectory(tests)
endif()

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)