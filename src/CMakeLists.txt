add_library(ncrypto ncrypto.cpp engine.cpp aead.cpp)

# Enable strict warning flags for ncrypto sources only
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang|AppleClang")
    target_compile_options(ncrypto PRIVATE
        -Werror
        -Wextra
        -Wno-unused-parameter
        -Wimplicit-fallthrough
        -Wno-deprecated-declarations  # OpenSSL 3.0 deprecates many APIs we intentionally use
    )
elseif(MSVC)
    target_compile_options(ncrypto PRIVATE
        /WX     # Treat warnings as errors
        /W3     # Warning level 3 (production quality)
        /wd4100 # Unreferenced formal parameter (like -Wno-unused-parameter)
        /wd4267 # Conversion from 'size_t' to smaller type
        /wd4244 # Conversion, possible loss of data
        /wd4305 # Truncation from 'int' to 'bool'
        /wd4127 # Conditional expression is constant
    )
endif()

if (NCRYPTO_SHARED_LIBS)
    target_link_libraries(ncrypto PUBLIC OpenSSL::SSL OpenSSL::Crypto)
else()
    target_link_libraries(ncrypto PUBLIC ssl crypto)

    if (NCRYPTO_BSSL_LIBDECREPIT_MISSING)
        target_compile_definitions(ncrypto PUBLIC NCRYPTO_BSSL_LIBDECREPIT_MISSING=1)
    else()
        target_link_libraries(ncrypto PUBLIC decrepit)
    endif()
endif()
target_include_directories(ncrypto
    PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}>
)
