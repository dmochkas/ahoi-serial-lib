cmake_minimum_required(VERSION 3.10)
project(ahoi_serial C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")

include(config.cmake)
include(GitAddSubmodule)
include(FetchContent)

set(ASCON_LIB_NAME "crypto_aead_${ALG_NAME}_${IMPL_LIST}")
set(AHOI_CORE_LIB_NAME "ahoi-core-lib")
set(LOG_LIB_NAME "zlog")

if (NOT TARGET ${LOG_LIB_NAME})
    FetchContent_Declare(
            zlog
            GIT_REPOSITORY https://github.com/HardySimpson/zlog.git
            GIT_TAG 1.2.18
    )

    FetchContent_MakeAvailable(zlog)

    target_include_directories(${LOG_LIB_NAME} PUBLIC "${PROJECT_BINARY_DIR}/_deps/zlog-src/src")
endif ()

add_library(${AHOI_LIB_NAME} STATIC)

add_git_submodule(DIRECTORY "thirdparty/ascon-c"
        PROPAGATE ON
        PATCHES "patches/ascon-fix.patch"
        CMP_TARGET ${ASCON_LIB_NAME})
add_subdirectory(src/ahoi_core)

target_sources(${AHOI_LIB_NAME} PRIVATE $<TARGET_OBJECTS:${AHOI_CORE_LIB_NAME}> $<TARGET_OBJECTS:${ASCON_LIB_NAME}>)
target_link_libraries(${AHOI_LIB_NAME} PRIVATE ${LOG_LIB_NAME})
target_include_directories(${AHOI_LIB_NAME} PUBLIC "${PROJECT_SOURCE_DIR}/include/pub")

if (ENABLE_TESTS)
    enable_testing()
    option(WITH_EXAMPLES "" OFF)
    if(NOT TARGET cmocka)
        add_git_submodule(DIRECTORY "thirdparty/cmocka"
                          PROPAGATE ON
                          CMP_TARGET "cmocka")
    endif ()
    add_subdirectory(tests)
endif ()