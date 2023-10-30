cmake_minimum_required(VERSION 3.0.0)
project(ratioNet VERSION 1.0.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fsanitize=undefined")

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

include(CTest)
enable_testing()

find_package(Boost REQUIRED COMPONENTS system)
find_package(OpenSSL REQUIRED)

set(TLS_VERSIONS tlsv11 tlsv12 tlsv13)
set(TLS_VERSION tlsv12 CACHE STRING "Specify the desired TLS version")
set_property(CACHE TLS_VERSION PROPERTY STRINGS ${TLS_VERSIONS})

option(ADD_COVERAGE "Add coverage" OFF)

message(STATUS "TLS version:            ${TLS_VERSION}")
message(STATUS "Add coverage:           ${ADD_COVERAGE}")

add_library(${PROJECT_NAME} INTERFACE)
target_include_directories(${PROJECT_NAME} INTERFACE $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>/include)
target_link_libraries(${PROJECT_NAME} INTERFACE Boost::system OpenSSL::SSL OpenSSL::Crypto)
target_compile_definitions(${PROJECT_NAME} INTERFACE TLS_VERSION=${TLS_VERSION})

if(BUILD_TESTING)
    add_subdirectory(tests)
endif()

if(MSVC)
    target_compile_options(${PROJECT_NAME} INTERFACE /W4)
else()
    target_compile_options(${PROJECT_NAME} INTERFACE -Wall -Wextra -pedantic)
    if (ADD_COVERAGE)
        if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
            target_compile_options(${PROJECT_NAME} PRIVATE --coverage)
            target_link_libraries(${PROJECT_NAME} PUBLIC gcov)
        endif()
    endif()
endif()

install(
    TARGETS ${PROJECT_NAME}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
install(
    FILES ${RATIONET_HEADERS}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/${PROJECT_NAME}
)

configure_package_config_file(src/${PROJECT_NAME}Config.cmake.in ${PROJECT_NAME}Config.cmake INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME} PATH_VARS CMAKE_INSTALL_INCLUDEDIR)
write_basic_package_version_file(${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake VERSION 1.0.0 COMPATIBILITY SameMajorVersion)
install(
    FILES ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}
)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)