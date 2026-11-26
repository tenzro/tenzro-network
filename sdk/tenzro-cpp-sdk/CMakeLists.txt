cmake_minimum_required(VERSION 3.16)
project(tenzro-cpp-sdk VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(TENZRO_BUILD_EXAMPLES "Build examples" ON)
option(TENZRO_BUILD_TESTS "Build tests" ON)

find_package(CURL 7.85 REQUIRED)

add_library(tenzro src/tenzro.c)
add_library(tenzro::tenzro ALIAS tenzro)
target_link_libraries(tenzro PUBLIC CURL::libcurl)
target_include_directories(tenzro PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>)
target_compile_options(tenzro PRIVATE -Wall -Wextra)

include(GNUInstallDirs)
install(TARGETS tenzro EXPORT tenzroTargets
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR} LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(DIRECTORY include/tenzro DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(EXPORT tenzroTargets NAMESPACE tenzro:: DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/tenzro)

if(TENZRO_BUILD_EXAMPLES)
  add_executable(tenzro_basic examples/basic/main.cpp)
  target_link_libraries(tenzro_basic PRIVATE tenzro)
  add_executable(tenzro_cuda_sample examples/cuda/main.cpp)
  target_link_libraries(tenzro_cuda_sample PRIVATE tenzro)
endif()

if(TENZRO_BUILD_TESTS)
  enable_testing()
  find_package(Threads REQUIRED)
  add_executable(test_offline tests/test_offline.cpp)
  target_link_libraries(test_offline PRIVATE tenzro Threads::Threads)
  target_compile_options(test_offline PRIVATE -UNDEBUG)
  add_test(NAME offline COMMAND test_offline)
endif()
