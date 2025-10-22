find_package(OpenSSL REQUIRED)
add_library(otto-crypt STATIC
    src/otto.c
)
target_include_directories(otto-crypt PUBLIC include)
target_link_libraries(otto-crypt PUBLIC OpenSSL::SSL OpenSSL::Crypto)

add_executable(otto-cli apps/otto_cli.c)
target_link_libraries(otto-cli PRIVATE otto-crypt OpenSSL::SSL OpenSSL::Crypto)
