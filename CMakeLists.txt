cmake_minimum_required(VERSION 3.25)
set(CMAKE_CXX_STANDARD 23)

project("netregu")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")

include_directories(include)
link_directories(${PROJECT_SOURCE_DIR}/lib)

file(GLOB SRC_FILES "src/*.cpp" "src/*.h")

add_executable(${PROJECT_NAME} ${SRC_FILES})

target_link_libraries(${PROJECT_NAME} WinDivert iphlpapi)

set_property(TARGET ${PROJECT_NAME} PROPERTY LINK_SEARCH_END_STATIC ON)
set_property(TARGET ${PROJECT_NAME} PROPERTY LINK_SEARCH_START_STATIC ON)