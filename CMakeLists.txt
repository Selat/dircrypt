cmake_minimum_required(VERSION 2.6)

project(dircrypt)

set(CMAKE_VERBOSE_MAKEFILE OFF)
set(CMAKE_BUILD_TYPE Release)
set(EXECUTABLE_OUTPUT_PATH "${PROJECT_SOURCE_DIR}/")

set(${PROJECT_NAME}_VERSION_MAJOR 0)
set(${PROJECT_NAME}_VERSION_MINOR 0)
set(${PROJECT_NAME}_VERSION_PATCH 1)
set(${PROJECT_NAME}_VERSION "${${PROJECT_NAME}_VERSION_MAJOR}.${${PROJECT_NAME}_VERSION_MINOR}.${${PROJECT_NAME}_VERSION_PATCH}")
message(STATUS "${PROJECT_NAME} ${${PROJECT_NAME}_VERSION}")

set(ADDITIONAL_LIBRARIES
  gcrypt
  )

set(CMAKE_C_FLAGS "-Wall -std=c99")
set(CMAKE_C_FLAGS_RELEASE "-O2")
set(CMAKE_C_FLAGS_DEBUG "-g")

set(SOURCES
  arg.c
  crypt.c
  fedi.c
  main.c
  tty.c
  settings.c)

add_executable(${PROJECT_NAME} ${SOURCES})
target_link_libraries(${PROJECT_NAME} ${ADDITIONAL_LIBRARIES})
