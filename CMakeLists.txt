cmake_minimum_required(VERSION 3.5)
project(CS671_Project1)

set(CMAKE_C_STANDARD 99)

set(SOURCE_FILES pid_analysis.c pid_analysis.h)
add_definitions(-D_GNU_SOURCE -Wall -O2)
add_executable(CS671_Project1 ${SOURCE_FILES})