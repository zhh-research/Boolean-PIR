find_package(OpenSSL REQUIRED)
find_package(PkgConfig REQUIRED)
find_package(Python3 3.10 REQUIRED COMPONENTS Interpreter)
find_package(Threads REQUIRED)
find_package(OpenMP REQUIRED COMPONENTS CXX)
pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium)

set(SPIRIT_SOURCE "${PROJECT_SOURCE_DIR}/.deps/SPIRIT" CACHE PATH "Pinned SPIRIT source")
set(SPIRIT_BUILD "${PROJECT_SOURCE_DIR}/.deps/spirit-build" CACHE PATH "Built SPIRIT")
find_package(SEAL 4.1.2 EXACT CONFIG REQUIRED
    PATHS "${SPIRIT_BUILD}/thirdparties/SEAL/cmake" NO_DEFAULT_PATH)

add_library(spirit_upstream STATIC IMPORTED)
set_target_properties(spirit_upstream PROPERTIES
    IMPORTED_LOCATION "${SPIRIT_BUILD}/lib/libSPIRIT.a"
    INTERFACE_INCLUDE_DIRECTORIES "${SPIRIT_SOURCE}/src")
target_link_libraries(spirit_upstream INTERFACE SEAL::seal OpenMP::OpenMP_CXX)

add_library(retrieval_crypto STATIC src/crypto.cpp)
target_link_libraries(retrieval_crypto PUBLIC OpenSSL::Crypto PkgConfig::SODIUM)

set(overlay "${CMAKE_CURRENT_BINARY_DIR}/overlay/batch_protocol.cpp")
add_custom_command(
    OUTPUT "${overlay}"
    COMMAND Python3::Interpreter "${CMAKE_CURRENT_SOURCE_DIR}/scripts/prepare_overlay.py"
        "${SPIRIT_SOURCE}" "${overlay}"
    DEPENDS scripts/prepare_overlay.py "${SPIRIT_SOURCE}/src/SPIRIT/pir/batch_protocol.cpp"
    VERBATIM)

set(hint_overlay "${CMAKE_CURRENT_BINARY_DIR}/overlay/public_matrix.cpp")
add_custom_command(
    OUTPUT "${hint_overlay}"
    COMMAND Python3::Interpreter "${CMAKE_CURRENT_SOURCE_DIR}/scripts/prepare_hint_overlay.py"
        "${SPIRIT_SOURCE}" "${hint_overlay}"
    DEPENDS scripts/prepare_hint_overlay.py "${SPIRIT_SOURCE}/src/SPIRIT/pir/public_matrix.cpp"
    VERBATIM)

add_executable(retrieval src/main.cpp src/spirit_adapter.cpp "${overlay}" "${hint_overlay}")
target_include_directories(retrieval PRIVATE src "${SPIRIT_SOURCE}/src/SPIRIT/pir")
target_compile_options(retrieval PRIVATE -march=native -Wall -Wextra -Wno-unused-function -Wno-unused-variable)
target_link_libraries(retrieval PRIVATE retrieval_crypto spirit_upstream Threads::Threads)

add_executable(index_benchmark src/index.cpp)
target_compile_options(index_benchmark PRIVATE -march=native)
