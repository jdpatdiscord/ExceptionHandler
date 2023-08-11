cmake_minimum_required(VERSION 3.15)

project(exceptionhandler LANGUAGES CXX)

#set(CMAKE_CXX_STANDARD_LIBRARIES "-ldbghelp -lstdc++ -lgcc -lgcc_s -lmingwex -lmingw32 -lmsvcrt -lkernel32 -lntdll")
set(CMAKE_CXX_STANDARD_LIBRARIES "${CMAKE_CXX_STANDARD_LIBRARIES} -ldbghelp -lZydis -lZycore")

option(ZYDIS_FEATURE_ENCODER "" OFF)
option(ZYDIS_FEATURE_DECODER "" ON)
option(ZYDIS_FEATURE_FORMATTER "" OFF)
option(ZYDIS_FEATURE_AVX512 "" ON)
option(ZYDIS_BUILD_TOOLS "" OFF)
option(ZYDIS_BUILD_EXAMPLES "" OFF)
option(ZYDIS_BUILD_MAN "" OFF)
option(ZYDIS_BUILD_DOXYGEN "" OFF)
option(ZYDIS_BUILD_TESTS "" OFF)
option(ZYDIS_BUILD_SHARED_LIB "" ON)

add_subdirectory(zydis/)

add_library(exceptionhandler_lib
    SHARED
    ExceptionHandler.hpp
    ExceptionHandler.cpp
    dll.cpp)

target_compile_options(exceptionhandler_lib PUBLIC -I${CMAKE_SOURCE_DIR}/zydis/include -I${CMAKE_SOURCE_DIR}/zydis/dependencies/zycore/include -Wall -Wextra -Oz -g0 -s)
target_link_options(exceptionhandler_lib PUBLIC -L${CMAKE_SOURCE_DIR}/build/zydis/ -L${CMAKE_SOURCE_DIR}/build/zydis/zycore)