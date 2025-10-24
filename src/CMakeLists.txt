add_library(ncrypto ncrypto.cpp engine.cpp)
target_link_libraries(ncrypto PUBLIC ssl crypto)

if (NCRYPTO_BSSL_LIBDECREPIT_MISSING)
    target_compile_definitions(ncrypto PUBLIC NCRYPTO_BSSL_LIBDECREPIT_MISSING=1)
else()
    target_link_libraries(ncrypto PUBLIC decrepit)
endif()

target_include_directories(ncrypto
    PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}>
)
