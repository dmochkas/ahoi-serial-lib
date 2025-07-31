add_library(${SENDER_LIB_NAME} OBJECT "sender.c")

target_include_directories(${SENDER_LIB_NAME} PRIVATE "${PROJECT_SOURCE_DIR}/include/priv")
target_include_directories(${SENDER_LIB_NAME} PRIVATE "${PROJECT_SOURCE_DIR}/include/pub/ahoi_serial")

target_sources(${SENDER_LIB_NAME} PRIVATE $<TARGET_OBJECTS:${COMMONS_LIB_NAME}>)