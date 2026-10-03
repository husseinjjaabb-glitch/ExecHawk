cmake_minimum_required(VERSION 3.20)
project(ExecHawk VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(CURL REQUIRED)
find_package(Threads REQUIRED)

add_executable(exec_hawk
    main.cpp
    core/engine.cpp
    agents/recon_hawk.cpp
    agents/vuln_hawk.cpp
    agents/exploit_hawk.cpp
    agents/post_hawk.cpp
    reporting/report_generator.cpp
)

target_link_libraries(exec_hawk
    CURL::libcurl
    Threads::Threads
)

# Dashboard
add_subdirectory(ui/react-dashboard)