# The name of our project is "SMLLIB". CMakeLists files in this project can
# refer to the root source directory of the project as ${SMLLIB_SOURCE_DIR} and
# to the root binary directory of the project as ${SMLLIB_BINARY_DIR}.
cmake_minimum_required (VERSION 2.8)

# include toolchain settings for AVR cross compile
IF (AVR)
  include(AVRToolchainConfig.cmake)
ENDIF ()


PROJECT(SMLLIB)

SET(CMAKE_PROJECT_VERSION "1.0")

# testing for windows x64 build
IF (${CMAKE_GENERATOR} MATCHES "Win64")
    set(WIN64 on)
ENDIF ()

# Use Doxygen for documentation (-> CMake module from http://tobias.rautenkranz.ch/cmake/doxygen/)
OPTION(DOXYGEN "Generate Doxygen documentation" off)
# switch Doxygen support automatically on for non-windows build
IF (NOT WIN32 AND NOT WIN64)
  SET(DOXYGEN on)
ENDIF ()
IF (DOXYGEN)
    set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}")
    include(UseDoxygen OPTIONAL)
ENDIF (DOXYGEN)

# Setup include directories
SET(SMLLIB_INCLUDE_DIR "${SMLLIB_SOURCE_DIR}/include")

# include compiler settings
INCLUDE(CMakeListsCompilerSettings.cmake)

# Specify available build types, relevant for windows builds
SET(BUILD_TYPES Debug Release MinSizeRel RelWithDebInfo)

# Setup output Directories
SET (CMAKE_LIBRARY_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/bin" CACHE PATH "Single Directory for all Libraries")
# Setup the Executable output Directory
SET (CMAKE_RUNTIME_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/bin" CACHE PATH "Single Directory for all Executables.")


ENABLE_TESTING()
# including the standard Dart testing module
INCLUDE(CTest)

# Recurse into the "src" subdirectory. This does not actually
# cause another cmake executable to run. The same process will walk through
# the project's entire directory structure.
ADD_SUBDIRECTORY("src")
#ADD_SUBDIRECTORY("src/tests")
