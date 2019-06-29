INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/third_debug/gmssl/include
        ${PROJECT_SOURCE_DIR}/public/common_utils)

LINK_DIRECTORIES(${PROJECT_SOURCE_DIR}/third_debug/gmssl/lib/linux
        ${PROJECT_SOURCE_DIR}/public/common_utils)

AUX_SOURCE_DIRECTORY(. CRYPTO_SRCS)

SET(DEPENDS crypto common_utils)

ADD_LIBRARY(cryptorgraphy SHARED ${CRYPTO_SRCS})
TARGET_LINK_LIBRARIES(cryptorgraphy ${DEPENDS})
