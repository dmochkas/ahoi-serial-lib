cmake_minimum_required(VERSION 3.10)
project(ahoi_serial C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")

include(config.cmake)
include(GitAddSubmodule)

set(ASCON_LIB_NAME "crypto_aead_${ALG_NAME}_${IMPL_LIST}")
set(COMMONS_LIB_NAME "ahoi-commons-lib")
set(SENDER_LIB_NAME "ahoi-sender-objects")
set(RECEIVER_LIB_NAME "ahoi-receiver-objects")

add_library(${AHOI_LIB_NAME} STATIC)

add_git_submodule(DIRECTORY "thirdparty/ascon-c"
        PROPAGATE ON
        PATCHES "patches/ascon-fix.patch"
        CMP_TARGET ${ASCON_LIB_NAME})
add_subdirectory(src/ahoi_commons)

if (WITH_SENDER)
    add_subdirectory(src/ahoi_sender)
    target_sources(${AHOI_LIB_NAME} PRIVATE $<TARGET_OBJECTS:${SENDER_LIB_NAME}> $<TARGET_OBJECTS:${COMMONS_LIB_NAME}> $<TARGET_OBJECTS:${ASCON_LIB_NAME}>)
endif ()

if (WITH_RECEIVER)
    add_subdirectory(src/ahoi_receiver)
    target_sources(${AHOI_LIB_NAME} PRIVATE $<TARGET_OBJECTS:${RECEIVER_LIB_NAME}> $<TARGET_OBJECTS:${COMMONS_LIB_NAME}> $<TARGET_OBJECTS:${ASCON_LIB_NAME}>)
endif ()

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