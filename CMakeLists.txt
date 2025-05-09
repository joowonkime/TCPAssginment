<<<<<<< HEAD
project(kens)

# Build KENS

set(kens_SOURCES TCPAssignment.cpp TCPAssignment.hpp)

add_library(kens SHARED ${kens_SOURCES})

target_link_libraries(kens PUBLIC e)

get_solution(kens)

# Tests

set(test_open_SOURCES testopen.cpp)
set(test_bind_SOURCES testbind.cpp)
set(test_handshake_SOURCES testhandshake.cpp)
set(test_close_SOURCES testclose.cpp)
set(test_transfer_SOURCES testtransfer.cpp)
set(test_congestion_SOURCES testcongestion.cpp)
set(test_all_SOURCES testopen.cpp testbind.cpp testhandshake.cpp testclose.cpp
                     testtransfer.cpp testcongestion.cpp)

set(kens-targets kens)

if(TARGET kens-ref)
  list(APPEND kens-targets kens-ref)
endif()

foreach(kens-traget ${kens-targets})
  foreach(
    part
    open
    bind
    handshake
    close
    transfer
    congestion
    all)

    add_executable(test-${kens-traget}-${part} testenv.hpp
                                               ${test_${part}_SOURCES})
    target_link_libraries(test-${kens-traget}-${part} ${kens-traget}
                          kens_solution gtest_main)
    add_executable(test-${kens-traget}-${part}-unreliable
                   testenv.hpp ${test_${part}_SOURCES})
    target_link_libraries(test-${kens-traget}-${part}-unreliable ${kens-traget}
                          kens_solution gtest_main)
    add_executable(test-${kens-traget}-${part}-run-solution
                   testenv.hpp ${test_${part}_SOURCES})
    target_link_libraries(test-${kens-traget}-${part}-run-solution
                          ${kens-traget} kens_solution gtest_main)
    add_executable(test-${kens-traget}-${part}-unreliable-run-solution
                   testenv.hpp ${test_${part}_SOURCES})
    target_link_libraries(test-${kens-traget}-${part}-unreliable-run-solution
                          ${kens-traget} kens_solution gtest_main)

    target_compile_definitions(test-${kens-traget}-${part}-run-solution
                               PRIVATE RUN_SOLUTION)
    target_compile_definitions(
      test-${kens-traget}-${part}-unreliable-run-solution PRIVATE RUN_SOLUTION
                                                                  UNRELIABLE)
    target_compile_definitions(test-${kens-traget}-${part}-unreliable
                               PRIVATE UNRELIABLE)

    if(${CMAKE_VERSION} VERSION_GREATER "3.13.0")
      set_target_properties(
        test-${kens-traget}-${part} test-${kens-traget}-${part}-run-solution
        test-${kens-traget}-${part}-unreliable
        test-${kens-traget}-${part}-unreliable-run-solution
        PROPERTIES XCODE_GENERATE_SCHEME ON)
      set_target_properties(
        test-${kens-traget}-${part} test-${kens-traget}-${part}-run-solution
        test-${kens-traget}-${part}-unreliable
        test-${kens-traget}-${part}-unreliable-run-solution
        PROPERTIES XCODE_SCHEME_ENVIRONMENT "GTEST_COLOR=no")
    endif()
  endforeach(part)
endforeach(kens-traget)
=======
cmake_minimum_required(VERSION 3.11)

project(e VERSION 3.3.7)

# Avoid warning about DOWNLOAD_EXTRACT_TIMESTAMP in CMake 3.24:
if(CMAKE_VERSION VERSION_GREATER_EQUAL "3.24.0")
  cmake_policy(SET CMP0135 NEW)
endif()

if(WIN32)
  message(
    FATAL_ERROR
      "WIN32 target is obsolete. Please use Windows Subsystems for Linux")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_C_STANDARD 11)

include(cmake/CPM.cmake)

option(SANITIZER "enable clang sanitzer (default: OFF)")
option(SOLUTION_PATH "custom solution path (default: OFF)")

if("${SANITIZER}" STREQUAL "address")
  message(STATUS "Sanitizer Selected: address")
  set(SANITIZER_FLAGS "-g -fsanitize=address -fno-omit-frame-pointer")
elseif("${SANITIZER}" STREQUAL "thread")
  message(STATUS "Sanitizer Selected: thread")
  set(SANITIZER_FLAGS "-g -fsanitize=thread")
elseif("${SANITIZER}" STREQUAL "memory")
  message(STATUS "Sanitizer Selected: memory")
  set(SANITIZER_FLAGS "-g -fsanitize=memory -fno-omit-frame-pointer")
elseif("${SANITIZER}" STREQUAL "undefined")
  message(STATUS "Sanitizer Selected: undefined")
  set(SANITIZER_FLAGS "-g -fsanitize=undefined")
endif()

if(SANITIZER_FLAGS)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${SANITIZER_FLAGS}")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${SANITIZER_FLAGS}")
  set(CMAKE_LINKER_FLAGS "${CMAKE_LINKER_FLAGS} ${SANITIZER_FLAGS}")
endif()

# Compiler Test

include(CheckCXXSourceCompiles)

check_cxx_source_compiles(
  "
    class a{
    int f(int leverl, const char *format, ...)
    __attribute__((format(printf, 3, 4)));
    };
    int main(void) {return 0;}
    "
  HAVE_ATTR_FORMAT)

if(HAVE_ATTR_FORMAT)
  add_compile_definitions(HAVE_ATTR_FORMAT)
endif()

check_cxx_source_compiles(
  "
    struct a{
    char b;
    long c;
    } __attribute__((packed));
    int main(void) {
      struct a a1;
      return 0;
    }
    "
  HAVE_ATTR_PACK)

check_cxx_source_compiles(
  "
    #pragma pack(push, 1)
    struct a{
      char b;
      long c;
    };
    #pragma pack(pop)
    int main(void) {
      struct a a1;
      return 0;
    }
    "
  HAVE_PRAGMA_PACK)

check_cxx_source_compiles(
  "
  #include <cassert>
  #include <cstring>
  #include <cxxabi.h>
  #include <typeinfo>
  struct aAa {};

  int main(void) {
    struct aAa a1;
    int status = -4;
    char *ret = abi::__cxa_demangle(typeid(a1).name(), NULL, NULL, &status);
    assert(std::strcmp(ret, \"aAa\") == 0);
    return 0;
  }
  "
  HAVE_DEMANGLE)

if(HAVE_ATTR_PACK)
  add_compile_definitions(HAVE_ATTR_PACK)
elseif(HAVE_PRAGMA_PACK)
  add_compile_definitions(HAVE_PRAGMA_PACK)
else()
  message(FATAL_ERROR "Compiler must support packing")
endif()

if(HAVE_DEMANGLE)
  add_compile_definitions(HAVE_DEMANGLE)
endif()

# Build E
file(GLOB_RECURSE e_SOURCES "src/*.cpp")

file(GLOB_RECURSE e_HEADERS "include/*.hpp")

add_library(e SHARED ${e_SOURCES} ${e_HEADERS})
target_include_directories(e PUBLIC ${PROJECT_SOURCE_DIR}/include)
find_package(Threads REQUIRED)
target_link_libraries(e PUBLIC Threads::Threads)

if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
  set_target_properties(e PROPERTIES OSX_ARCHITECTURES "arm64;x86_64")

endif()
target_compile_options(e PRIVATE -g -O0 -Wall)

# Get Library: GTest
CPMAddPackage(
  NAME googletest
  GITHUB_REPOSITORY google/googletest
  GIT_TAG v1.16.0
  VERSION 1.16.0
  OPTIONS "INSTALL_GTEST OFF" "gtest_force_shared_crt"
)

# Find Solution
function(get_solution_name TARGET)
  if(CMAKE_CXX_COMPILER_ID STREQUAL "AppleClang" AND CMAKE_SYSTEM_NAME STREQUAL
                                                     "Darwin")
    set(${TARGET}_SOLUTION_NAME
        "${TARGET}-universal-${CMAKE_SYSTEM_NAME}-${CMAKE_CXX_COMPILER_ID}.zip"
        PARENT_SCOPE)
  elseif((CMAKE_CXX_COMPILER_ID STREQUAL "MSVC" OR CMAKE_CXX_COMPILER_ID
                                                   STREQUAL "Clang")
         AND CMAKE_SYSTEM_NAME STREQUAL "Windows")
    set(${TARGET}_SOLUTION_NAME
        "${TARGET}-${CMAKE_SYSTEM_PROCESSOR}-${CMAKE_SYSTEM_NAME}-Clang.zip"
        PARENT_SCOPE)
  elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" OR CMAKE_CXX_COMPILER_ID STREQUAL
                                                 "Clang")
    string(REPLACE "." ";" CMAKE_CXX_COMPILER_VERSION_LIST
                   "${CMAKE_CXX_COMPILER_VERSION}")
    list(GET CMAKE_CXX_COMPILER_VERSION_LIST 0 CMAKE_CXX_COMPILER_VERSION_MAJOR)
    set(${TARGET}_SOLUTION_NAME
        "${TARGET}-${CMAKE_SYSTEM_PROCESSOR}-${CMAKE_SYSTEM_NAME}-${CMAKE_CXX_COMPILER_ID}-${CMAKE_CXX_COMPILER_VERSION_MAJOR}.zip"
        PARENT_SCOPE)
  else()
    set(${TARGET}_SOLUTION_NAME
        "${TARGET}-${CMAKE_SYSTEM_PROCESSOR}-${CMAKE_SYSTEM_NAME}-${CMAKE_CXX_COMPILER_ID}.zip"
        PARENT_SCOPE)
  endif()
endfunction()

# Build Solutions (If exists)
file(GLOB_RECURSE e_solution_CMAKELISTS
     "${PROJECT_SOURCE_DIR}/solution/*/CMakeLists.txt")

foreach(cmakelists ${e_solution_CMAKELISTS})
  get_filename_component(e_solution_DIR ${cmakelists} DIRECTORY)
  add_subdirectory(${e_solution_DIR})
endforeach()

# Solution Downloader

include(FetchContent)
function(get_solution)
  set(SOLUTION_REPO
      "https://anlab-kaist.github.io/KENSv3/solution/${CMAKE_PROJECT_VERSION}")
  foreach(arg IN LISTS ARGN)

    # Find Solution
    if(NOT TARGET ${arg}_solution)
      find_library(${arg}_solution_path ${arg}_solution PATH ${SOLUTION_PATH}
                   EXACT)

      if(NOT ${arg}_solution_path)
        # Download Solution
        message(STATUS "Donwloading ${arg}_solution")
        get_solution_name(${arg}_solution)

        include(FetchContent)

        FetchContent_Declare(
          ${arg}_solution
          URL "${SOLUTION_REPO}/${${arg}_solution_SOLUTION_NAME}")
        FetchContent_GetProperties(${arg}_solution)
        if(NOT (${arg}_solution_POPULATED))
          FetchContent_Populate(${arg}_solution)
        endif()

        find_library(${arg}_solution_path ${arg}_solution PATH
                     ${${arg}_solution_SOURCE_DIR} EXACT)
      endif()
      add_library(${arg}_solution SHARED IMPORTED GLOBAL)
      set_property(TARGET ${arg}_solution PROPERTY IMPORTED_LOCATION
                                                   ${${arg}_solution_path})

      target_link_libraries(${arg}_solution INTERFACE e)
    endif()
  endforeach()
endfunction()

# Build Apps

include(cmake/app-ref.cmake OPTIONAL)
if(e_apps_CMAKELISTS)

else()
  file(GLOB e_apps_CMAKELISTS "${PROJECT_SOURCE_DIR}/app/*/CMakeLists.txt")
endif()

list(FILTER e_apps_CMAKELISTS EXCLUDE REGEX ".*/scheduling/.*")

foreach(cmakelists ${e_apps_CMAKELISTS})
  get_filename_component(e_apps_DIR ${cmakelists} DIRECTORY)
  add_subdirectory(${e_apps_DIR})
endforeach()

find_package(Doxygen)
if(DOXYGEN_FOUND)

  add_custom_target(
    doxygen
    COMMAND
      ${CMAKE_COMMAND} -E env
      "DOXYGEN_OUTPUT_DIRECTORY=${PROJECT_BINARY_DIR}/doc" doxygen
      ${PROJECT_SOURCE_DIR}/doxygen/Doxyfile
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR})

endif()

include(cmake/kens-dist.cmake OPTIONAL)
>>>>>>> 6ed4df8 (debug start)
