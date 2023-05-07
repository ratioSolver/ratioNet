add_executable(rationet_tests test_rationet.cpp)
target_link_libraries(rationet_tests PRIVATE ratioNet)

add_test(NAME rationetTest00 COMMAND rationet_tests)