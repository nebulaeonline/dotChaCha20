cmake_minimum_required(VERSION 3.22)
project(dotChaCha20Native LANGUAGES CXX)

set(BORINGSSL_SOURCE_DIR
    "${CMAKE_CURRENT_SOURCE_DIR}/../../boringssl-rob"
    CACHE PATH "Path to the BoringSSL source tree")
set(DOTCHACHA_ARCH "" CACHE STRING "Native target architecture: x64 or arm64")

if(APPLE AND CMAKE_OSX_ARCHITECTURES MATCHES ";")
  message(FATAL_ERROR
      "Build one architecture per RID; do not use a universal CMAKE_OSX_ARCHITECTURES value.")
endif()

if(NOT EXISTS "${BORINGSSL_SOURCE_DIR}/gen/crypto")
  message(FATAL_ERROR
      "BORINGSSL_SOURCE_DIR must point to the BoringSSL source tree containing gen/crypto")
endif()

if(DOTCHACHA_ARCH STREQUAL "")
  string(TOLOWER
      "${CMAKE_SYSTEM_PROCESSOR};${CMAKE_GENERATOR_PLATFORM};${CMAKE_OSX_ARCHITECTURES}"
      _dotchacha_platform)
  if(_dotchacha_platform MATCHES "arm64|aarch64")
    set(DOTCHACHA_ARCH arm64)
  elseif(_dotchacha_platform MATCHES "x86_64|amd64|x64")
    set(DOTCHACHA_ARCH x64)
  else()
    message(FATAL_ERROR
        "Cannot determine architecture from '${_dotchacha_platform}'. Set DOTCHACHA_ARCH to x64 or arm64.")
  endif()
endif()

if(NOT DOTCHACHA_ARCH MATCHES "^(x64|arm64)$")
  message(FATAL_ERROR "DOTCHACHA_ARCH must be x64 or arm64, not '${DOTCHACHA_ARCH}'")
endif()

if(DOTCHACHA_ARCH STREQUAL "x64")
  if(WIN32)
    enable_language(ASM_NASM)
    set(_chacha_asm "${BORINGSSL_SOURCE_DIR}/gen/crypto/chacha-x86_64-win.asm")
    set_source_files_properties("${_chacha_asm}" PROPERTIES LANGUAGE ASM_NASM)
  elseif(APPLE)
    enable_language(ASM)
    set(_chacha_asm "${BORINGSSL_SOURCE_DIR}/gen/crypto/chacha-x86_64-apple.S")
  elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    enable_language(ASM)
    set(_chacha_asm "${BORINGSSL_SOURCE_DIR}/gen/crypto/chacha-x86_64-linux.S")
  else()
    message(FATAL_ERROR "x64 builds are supported on Windows, Linux, and macOS")
  endif()
  set(_chacha_compile_definition CHACHA20_NATIVE_AVX2)
else()
  if(WIN32)
    enable_language(ASM)
    set(_chacha_asm "${BORINGSSL_SOURCE_DIR}/gen/crypto/chacha-armv8-win.S")
  elseif(APPLE)
    enable_language(ASM)
    set(_chacha_asm "${BORINGSSL_SOURCE_DIR}/gen/crypto/chacha-armv8-apple.S")
  elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    enable_language(ASM)
    set(_chacha_asm "${BORINGSSL_SOURCE_DIR}/gen/crypto/chacha-armv8-linux.S")
  else()
    message(FATAL_ERROR "arm64 builds are supported on Windows, Linux, and macOS")
  endif()
  set(_chacha_compile_definition CHACHA20_NATIVE_NEON)
endif()

if(NOT EXISTS "${_chacha_asm}")
  message(FATAL_ERROR "BoringSSL assembly source not found: ${_chacha_asm}")
endif()

if(WIN32 AND DOTCHACHA_ARCH STREQUAL "arm64"
    AND CMAKE_GENERATOR MATCHES "Visual Studio")
  set(_chacha_object "${CMAKE_CURRENT_BINARY_DIR}/chacha-armv8-win.obj")
  if(CMAKE_ASM_COMPILER_TARGET STREQUAL "")
    set(CMAKE_ASM_COMPILER_TARGET aarch64-pc-windows-msvc)
  endif()
  add_custom_command(
      OUTPUT "${_chacha_object}"
      COMMAND "${CMAKE_ASM_COMPILER}"
          "--target=${CMAKE_ASM_COMPILER_TARGET}"
          -I "${BORINGSSL_SOURCE_DIR}/include"
          -c "${_chacha_asm}" -o "${_chacha_object}"
      DEPENDS "${_chacha_asm}"
      VERBATIM)
  set_source_files_properties("${_chacha_object}" PROPERTIES
      GENERATED TRUE
      EXTERNAL_OBJECT TRUE)
  set(_chacha_source "${_chacha_object}")
else()
  set(_chacha_source "${_chacha_asm}")
endif()

add_library(chacha20 SHARED
    "${CMAKE_CURRENT_SOURCE_DIR}/chacha20_export.cc"
    "${_chacha_source}")
target_compile_features(chacha20 PRIVATE cxx_std_11)
target_compile_definitions(chacha20 PRIVATE "${_chacha_compile_definition}")
target_include_directories(chacha20 PRIVATE "${BORINGSSL_SOURCE_DIR}/include")
set_target_properties(chacha20 PROPERTIES
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN YES)
if(WIN32)
  set_target_properties(chacha20 PROPERTIES PREFIX "")
endif()

install(TARGETS chacha20
    RUNTIME DESTINATION native
    LIBRARY DESTINATION native)
