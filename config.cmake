
# Ascon config
set(ALG_NAME "asconaead128" CACHE STRING "Name of the algorithm to build")
set(IMPL_NAME "opt64" CACHE STRING "Name of the architecture")
set(ALG_LIST ${ALG_NAME} CACHE STRING "")
set(IMPL_LIST ${IMPL_NAME} CACHE STRING "")
set(TEST_LIST "" CACHE STRING "")

# App config
option(ENABLE_TESTS "Enable testing" OFF)
# Deprecated
option(WITH_TIMING "R-Ack doesn't work. To calculate RTT from OS" OFF)
option(SECURE_MODE "Enable Ascon AEAD" ON)

set(AHOI_LIB_NAME "ahoi-serial-lib" CACHE STRING "Library name")