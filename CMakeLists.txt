project(gpg_example)
cmake_minimum_required(VERSION 2.8)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -D_FILE_OFFSET_BITS=64")

add_executable(gpg_example main.cpp)
target_link_libraries(gpg_example gpgme)

