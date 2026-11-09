cmake_minimum_required(VERSION 3.25)
project(agent-jail VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_compile_options(
    -Wall
    -Wextra
    -Werror
    -pedantic
    -O2
    -fno-exceptions
    -fno-rtti
    -pipe
)

include_directories(include)

set(SOURCES
    src/fsm.cpp
    src/cgroup.cpp
    src/pty.cpp
    src/vfs.cpp
    src/landlock.cpp
    src/main.cpp
)

add_executable(agent-jail ${SOURCES})
target_link_libraries(agent-jail PRIVATE util)

install(TARGETS agent-jail DESTINATION ~/.local/bin)
