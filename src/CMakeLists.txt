add_library(ncrypto ncrypto.cpp) target_include_directories(
    ncrypto PUBLIC $<BUILD_INTERFACE : ${PROJECT_SOURCE_DIR} / include>
        $<INSTALL_INTERFACE : ${CMAKE_INSTALL_INCLUDEDIR}>)
