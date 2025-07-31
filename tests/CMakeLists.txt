
set(SECURITY_TEST_NAME "security_test")

add_executable(${SECURITY_TEST_NAME} security_test.c)

target_link_libraries(${SECURITY_TEST_NAME} cmocka)

target_include_directories(${SECURITY_TEST_NAME} PRIVATE "${PROJECT_SOURCE_DIR}/include/priv")
target_include_directories(${SECURITY_TEST_NAME} PRIVATE "${PROJECT_SOURCE_DIR}/include/pub/ahoi_serial")
target_sources(${SECURITY_TEST_NAME} PRIVATE $<TARGET_OBJECTS:${COMMONS_LIB_NAME}>)

if(${CMAKE_VERSION} VERSION_GREATER_EQUAL "3.13.0")
    target_link_options(${SECURITY_TEST_NAME} PRIVATE $<$<CONFIG:DEBUG>:-fsanitize=address,undefined>)
endif ()

target_link_libraries(${SECURITY_TEST_NAME} ${ASCON_LIB_NAME})

add_test(NAME ${SECURITY_TEST_NAME} COMMAND ${SECURITY_TEST_NAME})

set(SEND_RCV_TEST_NAME "send_rcv_test")

add_executable(${SEND_RCV_TEST_NAME} send_rcv_test.c ${PROJECT_SOURCE_DIR}/src/ahoi_sender/sender.c)
target_link_libraries(${SEND_RCV_TEST_NAME} cmocka ${ASCON_LIB_NAME})
target_include_directories(${SEND_RCV_TEST_NAME} PRIVATE "${PROJECT_SOURCE_DIR}/include/priv")
target_include_directories(${SEND_RCV_TEST_NAME} PRIVATE "${PROJECT_SOURCE_DIR}/include/pub/ahoi_serial")
target_sources(${SEND_RCV_TEST_NAME} PRIVATE $<TARGET_OBJECTS:${COMMONS_LIB_NAME}>)

if(${CMAKE_VERSION} VERSION_GREATER_EQUAL "3.13.0")
    target_link_options(${SEND_RCV_TEST_NAME} PRIVATE $<$<CONFIG:DEBUG>:-fsanitize=address,undefined>)
endif()

add_test(NAME ${SEND_RCV_TEST_NAME} COMMAND ${SEND_RCV_TEST_NAME})
