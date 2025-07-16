function(add_git_submodule)
    cmake_parse_arguments(add_submodule "" "DIRECTORY;PROPAGATE;CMP_TARGET" "PATCHES" ${ARGN})

    if (NOT DEFINED add_submodule_DIRECTORY)
        message(FATAL_ERROR "Missing required argument: DIRECTORY")
    endif ()

    if (NOT DEFINED add_submodule_PROPAGATE)
        option(add_submodule_PROPAGATE "Add cloned project as cmake submodule" ON)
    endif ()

    find_package(Git REQUIRED)

    set(FULL_DIR ${PROJECT_SOURCE_DIR}/${add_submodule_DIRECTORY})

    if (NOT DEFINED add_submodule_CMP_TARGET OR NOT TARGET ${add_submodule_CMP_TARGET})
        message(STATUS "Cloning ${FULL_DIR} submodule")
        execute_process(COMMAND ${GIT_EXECUTABLE} submodule update --init --recursive -- ${FULL_DIR}
                WORKING_DIRECTORY ${PROJECT_SOURCE_DIR})

        foreach (patch IN LISTS add_submodule_PATCHES)
            message(STATUS "Applying patch ${patch}")
            execute_process(COMMAND ${GIT_EXECUTABLE} apply ${patch}
                            WORKING_DIRECTORY ${PROJECT_SOURCE_DIR})
        endforeach ()
    endif ()

    if (add_submodule_PROPAGATE)
        message(STATUS "Adding ${add_submodule_DIRECTORY} subdirectory to the tree")
        add_subdirectory(${FULL_DIR})
    endif ()
endfunction()