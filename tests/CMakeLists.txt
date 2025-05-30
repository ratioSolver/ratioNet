# add_executable(server_tests test_server.cpp)
# add_dependencies(server_tests ratioNet)
# target_link_libraries(server_tests PRIVATE ratioNet)
# setup_sanitizers(server_tests)

add_executable(client_tests test_client.cpp)
add_dependencies(client_tests ratioNet)
target_link_libraries(client_tests PRIVATE ratioNet)
setup_sanitizers(client_tests)

# add_test(NAME serverTest00 COMMAND server_tests WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
add_test(NAME clientTest00 COMMAND client_tests WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})