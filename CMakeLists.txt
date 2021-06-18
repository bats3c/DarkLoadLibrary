cmake_minimum_required(VERSION 3.15.0)

project(DarkLoadLibrary)
set(CMAKE_C_STANDARD 11)

file(GLOB_RECURSE C_SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/src/**.c)

add_library(
    ${PROJECT_NAME} STATIC ${C_SOURCE})

target_include_directories(${PROJECT_NAME} 
    PUBLIC 
        $<INSTALL_INTERFACE:include> 
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)

add_subdirectory(tests)
