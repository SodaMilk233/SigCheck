cmake_minimum_required(VERSION 3.22.1)
project(SignVerify)

set(CMAKE_C_STANDARD 17)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2 -fvisibility=hidden -Wall -Wextra -fomit-frame-pointer -fdata-sections -ffunction-sections -fno-asynchronous-unwind-tables -fno-unwind-tables")

set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,--strip-all -Wl,--gc-sections -Wl,-z,now -Wl,-z,relro -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/hide_map.txt")

find_library(log-lib log)

add_library(SignVerify SHARED
    main.c
    utils/syscall.c
    utils/memutil.c
    utils/strutil.c
    utils/sysutil.c
    detector/proxy_check.c
    detector/library_check.c
    detector/lsposed_check.c
    detector/riskmem_check.c
    detector/sandbox_check.c
    detector/seccomp_check.c
    signature/crypto/sha256.c
    signature/binder/binder.c
    signature/binder/parcel.c
    signature/binder/pkginfo.c
)

target_include_directories(SignVerify PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/utils
    ${CMAKE_CURRENT_SOURCE_DIR}/detector
    ${CMAKE_CURRENT_SOURCE_DIR}/signature/binder
    ${CMAKE_CURRENT_SOURCE_DIR}/signature/crypto
)

target_link_libraries(SignVerify ${log-lib})