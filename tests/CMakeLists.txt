add_executable(server_tests test_server.cpp)
target_link_libraries(server_tests PRIVATE ratioNet)

add_test(NAME serverTest00 COMMAND server_tests WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})