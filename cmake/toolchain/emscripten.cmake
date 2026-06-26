# cmake/toolchain/emscripten.cmake
# CMake toolchain file for Emscripten (wasm32-unknown-emscripten).
#
# Usage:
#   emcmake cmake <source_dir> -B <build_dir> \
#       -DCMAKE_TOOLCHAIN_FILE=cmake/toolchain/emscripten.cmake \
#       -DOPENSSL_ROOT_DIR=<path_to_openssl_wasm>
#
# Or let build-wasm.sh pass all required flags automatically.

set(CMAKE_SYSTEM_NAME Emscripten)
set(CMAKE_SYSTEM_VERSION 1)
set(EMSCRIPTEN 1)

# Locate emcc — must be in PATH (provided by emcmake wrapper or manual source)
find_program(EMCC emcc REQUIRED)
get_filename_component(EMSCRIPTEN_ROOT "${EMCC}" DIRECTORY)

set(CMAKE_C_COMPILER   "${EMSCRIPTEN_ROOT}/emcc")
set(CMAKE_CXX_COMPILER "${EMSCRIPTEN_ROOT}/em++")
set(CMAKE_AR           "${EMSCRIPTEN_ROOT}/emar"    CACHE FILEPATH "Emscripten archiver")
set(CMAKE_RANLIB       "${EMSCRIPTEN_ROOT}/emranlib" CACHE FILEPATH "Emscripten ranlib")
set(CMAKE_NM           "${EMSCRIPTEN_ROOT}/emnm"    CACHE FILEPATH "Emscripten nm")

# Emscripten sets __EMSCRIPTEN__ automatically; confirm cross-compiling
set(CMAKE_CROSSCOMPILING TRUE)

# Allow try_run() tests to execute via Node.js if needed.
# Most feature tests are bypassed by CompilerOptions.cmake when EMSCRIPTEN is set.
set(CMAKE_CROSSCOMPILING_EMULATOR "node;--experimental-wasm-bigint"
    CACHE STRING "Emulator for cross-compiled executables")

# Search only in Emscripten sysroot for libraries and includes; use host for programs
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
