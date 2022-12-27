# CMakeList.txt : CMake project for password_generator, include source and define
# project specific logic here.
#

#find_package(OpenSSL REQUIRED)
#find_package(cryptopp CONFIG REQUIRED)
#find_package(hydrogen CONFIG REQUIRED)
find_package(unofficial-sodium REQUIRED)

# Disable clip examples and tests
set(CLIP_EXAMPLES OFF)
set(CLIP_TESTS OFF)
# Add clip
add_subdirectory(clip)

# Add source to this project's executable.
add_executable (${PROJECT_NAME} "password_generator.cpp" "password_generator.h")

if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET ${PROJECT_NAME} PROPERTY CXX_STANDARD 20)
endif()

target_link_libraries(${PROJECT_NAME} PRIVATE clip unofficial-sodium::sodium) #OpenSSL::SSL OpenSSL::Crypto cryptopp-static hydrogen::hydrogen
# TODO: Add tests and install targets if needed.
