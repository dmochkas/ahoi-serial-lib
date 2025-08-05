add_library(${AHOI_CORE_LIB_NAME} OBJECT
        "core.c"
        "com.c"
        "cmd.c"
        "security.c")

target_include_directories(${AHOI_CORE_LIB_NAME} PRIVATE "${PROJECT_SOURCE_DIR}/include/pub/ahoi_serial")
target_include_directories(${AHOI_CORE_LIB_NAME} PRIVATE "${PROJECT_SOURCE_DIR}/include/priv")

target_link_libraries(${AHOI_CORE_LIB_NAME} PRIVATE ${ASCON_LIB_NAME})

if (SECURE_MODE)
    target_compile_definitions(${AHOI_CORE_LIB_NAME} PUBLIC SECURE_MODE=1)
endif ()