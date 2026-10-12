cmake_minimum_required(VERSION 3.16)

# espcoredump and esp_gdbstub make the core dump and GDB stub options available (debug guide).
set(COMPONENTS main espcoredump esp_gdbstub)
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(cryptose_tp2_benchmark)
