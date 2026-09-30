cmake_minimum_required(VERSION 3.20)

project(fiddler_browser_proxy LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(IMPERSONATE_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/libcurl-impersonate-v2.2.3.x86_64-win32")
if(NOT EXISTS "${IMPERSONATE_ROOT}/include/curl/curl.h")
    message(FATAL_ERROR "libcurl-impersonate-v2.2.3.x86_64-win32 was not found")
endif()

add_executable(fiddler-impersonate-proxy src/main.cpp)
target_include_directories(fiddler-impersonate-proxy PRIVATE "${IMPERSONATE_ROOT}/include")
target_link_libraries(fiddler-impersonate-proxy PRIVATE
    "${IMPERSONATE_ROOT}/lib/libcurl-impersonate_imp.lib"
    ws2_32
)

if(MSVC)
    target_compile_options(fiddler-impersonate-proxy PRIVATE /W4 /permissive- /utf-8)
endif()

add_custom_command(TARGET fiddler-impersonate-proxy POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${IMPERSONATE_ROOT}/lib/libcurl-impersonate.dll"
        "$<TARGET_FILE_DIR:fiddler-impersonate-proxy>"
)
