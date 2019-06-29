INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/third_debug/gmssl/include
        ${PROJECT_SOURCE_DIR}/public/cryptography
        ${PROJECT_SOURCE_DIR}/public/common_utils)

LINK_DIRECTORIES(${PROJECT_SOURCE_DIR}/third_debug/gmssl/lib/linux
        ${PROJECT_SOURCE_DIR}/public/cryptography
        ${PROJECT_SOURCE_DIR}/public/common_utils)

AUX_SOURCE_DIRECTORY(. CRYPTO_TOOLS_SRCS)

SET(depends crypto cryptorgraphy)

ADD_EXECUTABLE(crypto_tools ${CRYPTO_TOOLS_SRCS})
TARGET_LINK_LIBRARIES(crypto_tools ${depends})
