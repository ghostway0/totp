cmake_minimum_required(VERSION 3.20)
project(totp CXX)

set(CMAKE_CXX_STANDARD 26)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Werror")

set(SOURCES src/main.cpp)

find_package(absl REQUIRED)

include_directories(
    /opt/homebrew/Cellar/libsodium/1.0.20/include
    /opt/homebrew/Cellar/inih/58/include
)

link_directories(
    /opt/homebrew/Cellar/libsodium/1.0.20/lib
)

add_executable(${PROJECT_NAME} ${SOURCES})

target_link_libraries(${PROJECT_NAME}
    absl::log
    absl::log_initialize
    sodium
    absl::base
    absl::strings
    absl::time
    absl::status
    absl::statusor
    absl::str_format
    absl::flags
    absl::flags_commandlineflag
    absl::flags_parse
)
