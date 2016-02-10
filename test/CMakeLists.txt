add_subdirectory(googletest/googletest)

include_directories(${gtest_SOURCE_DIR}/include)
include_directories(..)

file(GLOB TEST_SOURCE_FILES "*.cpp") # All files in directory:
add_executable(run_tests ${TEST_SOURCE_FILES})
target_link_libraries(run_tests
						gtest
						gtest_main
						c_gpgme
						gpgme
						boost_filesystem
						boost_system)