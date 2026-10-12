cmake_minimum_required(VERSION 3.20)

project(cryptose_benchmark_host_tests LANGUAGES C)

enable_testing()

add_executable(test_jsonl test_jsonl.c ../main/jsonl.c)
target_include_directories(test_jsonl PRIVATE ../main)
target_compile_features(test_jsonl PRIVATE c_std_11)
target_compile_options(test_jsonl PRIVATE -Wall -Wextra -Wpedantic -Werror)

add_test(NAME jsonl_contract COMMAND test_jsonl)

add_executable(test_statistics test_statistics.c ../main/statistics.c)
target_include_directories(test_statistics PRIVATE ../main)
target_compile_features(test_statistics PRIVATE c_std_11)
target_compile_options(test_statistics PRIVATE -Wall -Wextra -Wpedantic -Werror)

add_test(NAME statistics_contract COMMAND test_statistics)
