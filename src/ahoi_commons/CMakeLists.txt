add_library(${COMMONS_LIB_NAME} OBJECT
        "core.c"
        "security.c")

target_include_directories(${COMMONS_LIB_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/include/ahoi_serial")
target_include_directories(${COMMONS_LIB_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/include/priv")

target_link_libraries(${COMMONS_LIB_NAME} PRIVATE ${ASCON_LIB_NAME})