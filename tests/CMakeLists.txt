add_executable(server_tests test_server.cpp)
target_link_libraries(server_tests PRIVATE ratioNet)

add_executable(client_tests test_client.cpp)
target_link_libraries(client_tests PRIVATE ratioNet)

add_executable(ws_client_tests test_ws.cpp)
target_link_libraries(ws_client_tests PRIVATE ratioNet)

add_test(NAME serverTest00 COMMAND server_tests WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
add_test(NAME clientTest00 COMMAND client_tests WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
add_test(NAME wsClientTest00 COMMAND ws_client_tests WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})