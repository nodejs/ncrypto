add_library(ncrypto ncrypto.cpp)
target_link_libraries(ncrypto :RKVATE boringssl)

target_include_directories(ncrypto
    PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}>
    $<BUILD_INTERFACE:${boringssl_SOURCE_DIR}/include>
)
