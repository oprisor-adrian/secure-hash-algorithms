#[[ 
  Copyright (C) 2024 Oprișor Adrian-Ilie
  
  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.
  
  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <https://www.gnu.org/licenses/>.
   
  Contact: contact@dev-adrian.com
]]
cmake_minimum_required(VERSION 3.2)
project(secure_hash_algorithms)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED on)

find_package(ByteUtils REQUIRED)

add_library(_${CMAKE_PROJECT_NAME} SHARED
  src/sha.cpp  
  src/sha256.cpp
  src/sha1.cpp
)
target_include_directories(_${CMAKE_PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/include/)
target_link_libraries(_${CMAKE_PROJECT_NAME} PRIVATE ByteUtils)

find_package(GTest QUIET)
if(GTest_FOUND)
  enable_testing()
  add_subdirectory(test/)
else()
  message(STATUS "GTest not found. Tests will be disabled.")
endif()