set(THREADS_USE_PTHREADS_WIN32 true)
find_package(Threads)

set(libs
    mbedtls
)

set(targets
    selftls
)

if(USE_PKCS11_HELPER_LIBRARY)
    set(libs ${libs} pkcs11-helper)
endif(USE_PKCS11_HELPER_LIBRARY)

if(ENABLE_ZLIB_SUPPORT)
    set(libs ${libs} ${ZLIB_LIBRARIES})
endif(ENABLE_ZLIB_SUPPORT)

add_executable(selftls selftls.c)
target_link_libraries(selftls ${libs})

install(TARGETS ${targets}
        DESTINATION "bin"
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

