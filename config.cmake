
# Ascon config
set(ALG_NAME "asconaead128" CACHE STRING "Name of the algorithm to build")
set(IMPL_NAME "opt64" CACHE STRING "Name of the architecture")
set(ALG_LIST ${ALG_NAME} CACHE STRING "")
set(IMPL_LIST ${IMPL_NAME} CACHE STRING "")
set(TEST_LIST "" CACHE STRING "")

# App config
option(WITH_SENDER "Build sender" ON)
option(WITH_RECEIVER "Build receiver" ON)
option(ENABLE_TESTS "Enable testing" ON)

set(AHOI_LIB_NAME "ahoi-serial-lib" CACHE STRING "Library name")