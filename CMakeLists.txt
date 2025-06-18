cmake_minimum_required(VERSION 3.10)
project(nids VERSION 1.0.0 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Add include directories
include_directories(${CMAKE_SOURCE_DIR}/include)

# Find required packages
find_package(PkgConfig REQUIRED)
pkg_check_modules(YAML REQUIRED yaml-cpp)
include_directories(${YAML_INCLUDE_DIRS})

# Find LibPCAP
find_path(PCAP_INCLUDE_DIR pcap.h)
find_library(PCAP_LIBRARY pcap)

if(NOT PCAP_INCLUDE_DIR OR NOT PCAP_LIBRARY)
    message(FATAL_ERROR "LibPCAP not found")
endif()

include_directories(${PCAP_INCLUDE_DIR})

# Set source files
set(SOURCES
    src/main.cpp
    src/nids.cpp
    src/packet_capture.cpp
    src/rule_engine.cpp
    src/alert_system.cpp
    src/log_manager.cpp
    src/config_manager.cpp
)

# Create executable
add_executable(nids ${SOURCES})

# Link libraries
target_link_libraries(nids ${PCAP_LIBRARY} ${YAML_LIBRARIES} pthread)

# Copy configuration files to build directory
file(COPY ${CMAKE_SOURCE_DIR}/config DESTINATION ${CMAKE_BINARY_DIR})

# Install targets
install(TARGETS nids DESTINATION bin)
install(DIRECTORY config/ DESTINATION /etc/nids)

# Create directory for logs
install(CODE "file(MAKE_DIRECTORY \${CMAKE_INSTALL_PREFIX}/var/log/nids)")

# Add testing
enable_testing()

# Add custom targets
add_custom_target(run
    COMMAND nids
    DEPENDS nids
    WORKING_DIRECTORY ${CMAKE_PROJECT_DIR}
)
