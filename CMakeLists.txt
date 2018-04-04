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
set(PROJECT_NAME silverstar)

project(${PROJECT_NAME})

set(CMAKE_CXX_STANDARD 17)

include(conanbuildinfo.cmake)
CONAN_BASIC_SETUP()

find_package(libmongocxx REQUIRED)
find_package(libbsoncxx REQUIRED)

set(SOURCE_FILES
        main.cpp
#        controllers/card_controller.cpp
#        controllers/card_controller.h
#        models/ability.cpp models/ability.h
        )

add_executable(${PROJECT_NAME} ${SOURCE_FILES})

target_include_directories(${PROJECT_NAME}
        PRIVATE ${LIBMONGOCXX_INCLUDE_DIRS}
        PRIVATE ${LIBBSONCXX_INCLUDE_DIRS}
        )

target_link_libraries(${PROJECT_NAME}
        PRIVATE ${CONAN_LIBS}
        PRIVATE ${LIBMONGOCXX_LIBRARIES}
        PRIVATE ${LIBBSONCXX_LIBRARIES}
        )

target_compile_definitions(${PROJECT_NAME}
        PRIVATE ${LIBMONGOCXX_DEFINITIONS}
        PRIVATE ${LIBBSONCXX_DEFINITIONS}
        )


# Tests
#add_subdirectory(tests)