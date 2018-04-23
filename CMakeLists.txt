#        _ _
#       (_) |
#    ___ _| |_   _____ _ __
#   / __| | \ \ / / _ \ '__|
#   \__ \ | |\ V /  __/ | |
#   |___/_|_| \_/ \___|_| |_ __ _ _ __
#                   / __| __/ _` | '__|
#                   \__ \ || (_| | |
#                   |___/\__\__,_|_|
#
#
#
#  silverstar
#  A web microservice for authenticating users
#
#  Copyright © 2018 D.E. Goodman-Wilson
#

cmake_minimum_required(VERSION 3.6)
project(silverstar)

set(CMAKE_CXX_STANDARD 17)

include(conanbuildinfo.cmake)
CONAN_BASIC_SETUP()

set(SOURCE_FILES
        main.cpp
        auth_controller.cpp auth_controller.h
        configuration.cpp configuration.h
        )

add_executable(${PROJECT_NAME} ${SOURCE_FILES})

target_link_libraries(${PROJECT_NAME}
        PRIVATE ${CONAN_LIBS}
        )


# Tests
#add_subdirectory(tests)