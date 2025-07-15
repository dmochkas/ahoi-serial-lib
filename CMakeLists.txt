cmake_minimum_required(VERSION 3.10)
project(ahoi_serial C)

include(config.cmake)

set(CMAKE_C_STANDARD 11)
set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

set(ASCON_LIB_NAME "crypto_aead_${ALG_NAME}_${IMPL_LIST}")
set(COMMONS_LIB_NAME "commons-lib")
#set(SENDER_TARGET "sender")
set(SENDER_LIB_NAME "sender-objects")
#set(RECEIVER_TARGET "receiver")
set(RECEIVER_LIB_NAME "receiver-objects")

add_library(${AHOI_LIB_NAME} STATIC)

add_subdirectory(src/ahoi_commons)

if (WITH_SENDER)
    add_subdirectory(src/ahoi_sender)
    target_sources(${AHOI_LIB_NAME} PRIVATE $<TARGET_OBJECTS:${SENDER_LIB_NAME}>)
endif ()


if (WITH_RECEIVER)
    add_subdirectory(src/ahoi_receiver)
    target_sources(${AHOI_LIB_NAME} PRIVATE $<TARGET_OBJECTS:${RECEIVER_LIB_NAME}>)
endif ()


