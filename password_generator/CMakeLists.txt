# CMakeList.txt : CMake project for password_generator, include source and define
# project specific logic here.
#

find_package(OpenSSL REQUIRED)

# Add source to this project's executable.
add_executable (${PROJECT_NAME} "password_generator.cpp" "password_generator.h"  )

if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET ${PROJECT_NAME} PROPERTY CXX_STANDARD 20)
endif()

target_link_libraries(${PROJECT_NAME} PRIVATE OpenSSL::SSL OpenSSL::Crypto)

# TODO: Add tests and install targets if needed.
