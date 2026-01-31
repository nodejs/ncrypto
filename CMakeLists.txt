cmake_minimum_required(VERSION 3.28)
project(ncrypto VERSION 1.1.0) # x-release-please-version

include(CTest)
include(GNUInstallDirs)
include(cmake/ncrypto-flags.cmake)

if (NOT CMAKE_BUILD_TYPE)
  message(STATUS "No build type selected, default to Release")
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build." FORCE)
endif()

if (NCRYPTO_SHARED_LIBS)
  find_package(OpenSSL REQUIRED)
else()
  include(FetchContent)
  include(cmake/CPM.cmake)

  CPMAddPackage(
    NAME boringssl
    VERSION 0.20250818.0
    GITHUB_REPOSITORY google/boringssl
    GIT_TAG 0.20250818.0
    OPTIONS "BUILD_SHARED_LIBS OFF" "BUILD_TESTING OFF"
  )
endif()

add_subdirectory(src)
add_library(ncrypto::ncrypto ALIAS ncrypto)

if (NCRYPTO_TESTING)
  if (NCRYPTO_SHARED_LIBS)
    find_package(GTest REQUIRED)
  else()
    CPMAddPackage(
      NAME GTest
      GITHUB_REPOSITORY google/googletest
      VERSION 1.15.2
      OPTIONS  "BUILD_GMOCK OFF" "INSTALL_GTEST OFF"
    )
    # For Windows: Prevent overriding the parent project's compiler/linker settings
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
  endif()
  enable_testing()
  add_subdirectory(tests)
endif()

install(
  FILES include/ncrypto.h
  DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
  COMPONENT ncrypto_development
)
install(
  DIRECTORY include/ncrypto
  DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
  COMPONENT ncrypto_development
)

install(
  TARGETS ncrypto
  EXPORT ncrypto_targets
  RUNTIME COMPONENT ncrypto_runtime
  LIBRARY COMPONENT ncrypto_runtime
  NAMELINK_COMPONENT ncrypto_development
  ARCHIVE COMPONENT ncrypto_development
  INCLUDES DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
)

# Generate pkg-config file
configure_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/ncrypto.pc.in
  ${CMAKE_CURRENT_BINARY_DIR}/ncrypto.pc
  @ONLY
)

install(
  FILES ${CMAKE_CURRENT_BINARY_DIR}/ncrypto.pc
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig
)
