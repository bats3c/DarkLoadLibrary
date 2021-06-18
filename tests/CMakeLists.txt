project(DarkLoadLibrary-Test)

add_executable(${PROJECT_NAME} main.c)
target_link_libraries(${PROJECT_NAME} DarkLoadLibrary)
target_include_directories(${PROJECT_NAME} PRIVATE ../include)
