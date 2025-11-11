cmake_minimum_required(VERSION 3.21)
project(ratioNet VERSION 0.2.0 LANGUAGES CXX)

include(CTest)
enable_testing()

include(FetchContent)
FetchContent_Declare(asio GIT_REPOSITORY https://github.com/chriskohlhoff/asio.git GIT_TAG asio-1-31-0)
FetchContent_MakeAvailable(asio)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/CTestCustom.cmake.in ${CMAKE_CURRENT_BINARY_DIR}/CTestCustom.cmake @ONLY)

add_library(asio INTERFACE)
target_compile_definitions(asio INTERFACE ASIO_STANDALONE)
target_include_directories(asio INTERFACE ${asio_SOURCE_DIR}/asio/include)

option(ENABLE_CORS "Enable Cross-Origin Resource Sharing (CORS)" OFF)
option(ENABLE_LOG "Enable logging functionality" OFF)
option(ENABLE_SSL "Enable Secure Sockets Layer (SSL) for secure communication" OFF)
set(SERVER_HOST "0.0.0.0" CACHE STRING "The address the server listens on")
set(SERVER_PORT "8080" CACHE STRING "The port the server listens on")

message(STATUS "Enable CORS: ${ENABLE_CORS}")
message(STATUS "Enable logging: ${ENABLE_LOG}")
message(STATUS "Enable SSL: ${ENABLE_SSL}")
message(STATUS "Server address: ${SERVER_HOST}")
message(STATUS "Server port: ${SERVER_PORT}")

if(ENABLE_SSL)
    find_package(OpenSSL REQUIRED)

    set(TLS_VERSIONS tlsv11 tlsv12 tlsv13)
    set(TLS_VERSION tlsv12 CACHE STRING "Specify the desired TLS version")
    set_property(CACHE TLS_VERSION PROPERTY STRINGS ${TLS_VERSIONS})
    if(NOT TLS_VERSION IN_LIST TLS_VERSIONS)
        message(FATAL_ERROR "Invalid TLS version specified")
    endif()
    message(STATUS "TLS version: ${TLS_VERSION}")
endif()

add_library(ratioNet src/server/server.cpp src/server/server_session.cpp src/server/ws_server_session.cpp src/client/async_client.cpp src/client/client_session.cpp src/client/ws_client_session.cpp src/client/client.cpp)
target_compile_features(ratioNet PUBLIC cxx_std_17)
target_include_directories(ratioNet PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include/common> $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include/server> $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include/client> $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include/middlewares>)
target_compile_definitions(ratioNet PUBLIC SERVER_HOST="${SERVER_HOST}" SERVER_PORT=${SERVER_PORT})
if(NOT TARGET json)
    add_subdirectory(extern/json)
    add_dependencies(ratioNet json)
endif()
target_link_libraries(ratioNet PUBLIC asio json)

if (ENABLE_CORS)
    target_sources(ratioNet PUBLIC src/middlewares/cors.cpp)
    target_compile_definitions(ratioNet PUBLIC ENABLE_CORS)
endif()

if (ENABLE_LOG)
    target_sources(ratioNet PUBLIC src/middlewares/log.cpp)
    target_compile_definitions(ratioNet PUBLIC ENABLE_LOG)
endif()

if (ENABLE_SSL)
    target_link_libraries(ratioNet PUBLIC OpenSSL::SSL OpenSSL::Crypto)
    target_compile_definitions(ratioNet PUBLIC ENABLE_SSL TLS_VERSION=${TLS_VERSION})
endif()

if(BUILD_TESTING)
    add_subdirectory(tests)
endif()

setup_sanitizers(ratioNet)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)