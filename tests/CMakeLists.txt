add_executable(server_tests test_server.cpp)
target_link_libraries(server_tests PRIVATE ratioNet)

add_executable(client_tests test_client.cpp)
target_link_libraries(client_tests PRIVATE ratioNet)

add_test(NAME serverTest00 COMMAND server_tests)
add_test(NAME clientTest00 COMMAND client_tests)