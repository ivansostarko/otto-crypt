add_executable(otto-demo demo.c)
target_link_libraries(otto-demo PRIVATE otto-crypt OpenSSL::SSL OpenSSL::Crypto)
