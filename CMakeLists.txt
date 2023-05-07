cmake_minimum_required(VERSION 3.0.0)
project(ratioNet VERSION 1.0.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

include(GenerateExportHeader)
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

find_package(Boost REQUIRED COMPONENTS system)

add_subdirectory(extern/json)

file(GLOB RATIONET_SOURCES src/*.cpp)
file(GLOB RATIONET_HEADERS include/*.h)

add_executable(${PROJECT_NAME} ${RATIONET_SOURCES})
target_include_directories(${PROJECT_NAME} PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>/include)
target_link_libraries(${PROJECT_NAME} json Boost::system)