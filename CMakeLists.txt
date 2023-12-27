cmake_minimum_required(VERSION 3.2)
project(sha256)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED on)
set(CMAKE_INSTALL_PREFIX ${CMAKE_SOURCE_DIR})

find_package(ByteUtils REQUIRED)

add_library(_${CMAKE_PROJECT_NAME} SHARED
  src/sha256.cpp
)
target_link_libraries(_${CMAKE_PROJECT_NAME} PRIVATE ByteUtils)

enable_testing()
add_subdirectory(test/)