cmake_minimum_required(VERSION 3.16)
project(otto-crypt-cpp LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)

add_library(otto-crypt STATIC
    src/otto.cpp
)
target_include_directories(otto-crypt PUBLIC include)
target_link_libraries(otto-crypt PUBLIC OpenSSL::SSL OpenSSL::Crypto)

add_executable(otto-cli apps/otto_cli.cpp)
target_link_libraries(otto-cli PRIVATE otto-crypt)

add_executable(otto-demo demo/otto_demo.cpp)
target_link_libraries(otto-demo PRIVATE otto-crypt)

install(TARGETS otto-cli RUNTIME DESTINATION bin)
install(TARGETS otto-demo RUNTIME DESTINATION bin)
install(TARGETS otto-crypt ARCHIVE DESTINATION lib LIBRARY DESTINATION lib)
install(DIRECTORY include/ DESTINATION include)
