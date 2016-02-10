cmake_minimum_required(VERSION 2.8)
project(gpg_example)


set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -D_FILE_OFFSET_BITS=64 -Wall -Wextra -pedantic")
add_subdirectory(test)

add_library(c_gpgme c_gpgme.cpp)
add_executable(gpg_example main.cpp)
target_link_libraries(gpg_example
						gpgme
						c_gpgme
						boost_system
						boost_filesystem)

add_custom_target(unit_test
        COMMAND ./run_tests
        DEPENDS test/run_tests
        WORKING_DIRECTORY ./test)
