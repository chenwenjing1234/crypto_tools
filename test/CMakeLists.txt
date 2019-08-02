INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/third_debug/gmssl/include)

LINK_DIRECTORIES(${PROJECT_SOURCE_DIR}/third_debug/gmssl/lib/linux)

AUX_SOURCE_DIRECTORY(. GMSSL_TEST_SRCS)

SET(depends crypto)

ADD_EXECUTABLE(tools_test ${GMSSL_TEST_SRCS})
TARGET_LINK_LIBRARIES(tools_test ${depends})
