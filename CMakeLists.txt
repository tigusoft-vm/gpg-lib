cmake_minimum_required(VERSION 2.8)
project(gpg_example)


set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -D_FILE_OFFSET_BITS=64 -Wall -Wextra -pedantic")
add_subdirectory(test)

add_executable(gpg_example c_gpgme.cpp main.cpp)
target_link_libraries(gpg_example gpgme)

