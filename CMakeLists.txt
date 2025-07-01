cmake_minimum_required(VERSION 3.10)
project(IIoT_MMT LANGUAGES C)

# Include paths for liboqs, OpenSSL, and pqc_kem
include_directories(
    /usr/local/include
    ${CMAKE_SOURCE_DIR}/src/pqc_kem
)

# Build static library for PQC KEM module
add_library(pqc_kem STATIC
    src/pqc_kem/pqc_kem.c
)

# Demo test executable
add_executable(kem_test scripts/kem_test.c)
target_link_libraries(kem_test PRIVATE pqc_kem oqs crypto)
set_target_properties(kem_test PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/scripts
)

# Main application executable
add_executable(main_app src/app/main.c)
target_link_libraries(main_app PRIVATE pqc_kem oqs crypto)
set_target_properties(main_app PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/scripts
)