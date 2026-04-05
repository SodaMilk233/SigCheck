#include "syscall.h"
#include <sys/mman.h>

typedef long (*syscall_fn)(long, long, long, long, long, long, long);

static volatile syscall_fn g_syscall_fn = NULL;

#define SVC_KEY 0x5A5A5A5AU
static const uint32_t code_enc[] = {
    0xAA0003E8U ^ SVC_KEY,
    0xAA0103E0U ^ SVC_KEY,
    0xAA0203E1U ^ SVC_KEY,
    0xAA0303E2U ^ SVC_KEY,
    0xAA0403E3U ^ SVC_KEY,
    0xAA0503E4U ^ SVC_KEY,
    0xAA0603E5U ^ SVC_KEY,
    0xD4000001U ^ SVC_KEY,
    0xD65F03C0U ^ SVC_KEY,
};

static void __attribute__((constructor)) init_syscall_trampoline(void) {
    const size_t n = sizeof(code_enc) / sizeof(code_enc[0]);
    uint32_t code[9];
    for (size_t i = 0; i < n; i++) {
        code[i] = code_enc[i] ^ SVC_KEY;
    }
    size_t code_size = sizeof(code);
    void* mem = mmap(NULL, code_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) return;
    __builtin_memcpy(mem, code, code_size);
    __clear_cache(mem, (char*)mem + code_size);
    if (mprotect(mem, code_size, PROT_READ | PROT_EXEC) != 0) {
        munmap(mem, code_size);
        return;
    }
    g_syscall_fn = (volatile syscall_fn)mem;
}

long syscall_invoke(long number, long arg1, long arg2, long arg3, long arg4, long arg5, long arg6) {
    if (!g_syscall_fn) return -1;
    return g_syscall_fn(number, arg1, arg2, arg3, arg4, arg5, arg6);
}
