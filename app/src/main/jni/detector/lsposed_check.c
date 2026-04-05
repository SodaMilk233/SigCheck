#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <jni.h>
#include <signal.h>
#include <setjmp.h>
#include "lsposed_check.h"
#include "utils/memutil.h"
#include "utils/strutil.h"
#include "syscall.h"

struct linux_dirent64 {
    unsigned long long d_ino;
    long long d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[256];
};

static int check_dev_zero_deleted(void) {
    int dir_fd = syscall_invoke(__NR_openat, AT_FDCWD, (long)"/proc/self/task", O_RDONLY | O_DIRECTORY, 0, 0, 0);
    if (dir_fd < 0) return 0;
    char path[256], buf[4096];
    struct linux_dirent64 *dir_entry;
    long nread;
    int found = 0;
    while ((nread = syscall_invoke(__NR_getdents64, dir_fd, (long)buf, (long)sizeof(buf), 0, 0, 0)) > 0) {
        for (long bpos = 0; bpos < nread;) {
            dir_entry = (struct linux_dirent64 *)(buf + bpos);
            if (dir_entry->d_name[0] >= '0' && dir_entry->d_name[0] <= '9') {
                int path_len = snprintf(path, sizeof(path), "/proc/self/task/%s/maps", dir_entry->d_name);
                if (path_len < 0 || path_len >= (int)sizeof(path)) {
                    bpos += dir_entry->d_reclen;
                    continue;
                }
                int maps_fd = syscall_invoke(__NR_openat, AT_FDCWD, (long)path, O_RDONLY, 0, 0, 0);
                if (maps_fd >= 0) {
                    ssize_t bytes_read;
                    while ((bytes_read = syscall_invoke(__NR_read, maps_fd, (long)buf, (long)sizeof(buf), 0, 0, 0)) > 0) {
                        if (my_memmem(buf, bytes_read, "/dev/zero (deleted)", 19)) {
                            found = 1;
                            break;
                        }
                    }
                    syscall_invoke(__NR_close, maps_fd, 0, 0, 0, 0, 0);
                    if (found) break;
                }
            }
            bpos += dir_entry->d_reclen;
        }
        if (found) break;
    }
    syscall_invoke(__NR_close, dir_fd, 0, 0, 0, 0, 0);
    return found;
}

static sigjmp_buf g_jmpbuf;
static void segv_handler(int sig) {
    (void)sig;
    siglongjmp(g_jmpbuf, 1);
}

static uint32_t safe_read_u32(void *addr) {
    struct sigaction sa_old, sa_new;
    memset(&sa_new, 0, sizeof(sa_new));
    sa_new.sa_handler = segv_handler;
    sigemptyset(&sa_new.sa_mask);
    sa_new.sa_flags = 0;
    if (sigsetjmp(g_jmpbuf, 1) == 0) {
        sigaction(SIGSEGV, &sa_new, &sa_old);
        uint32_t val = *(volatile uint32_t *)addr;
        sigaction(SIGSEGV, &sa_old, NULL);
        return val;
    } else {
        sigaction(SIGSEGV, &sa_old, NULL);
        return 0xFFFFFFFF;
    }
}

static uint64_t safe_read_u64(void *addr) {
    struct sigaction sa_old, sa_new;
    memset(&sa_new, 0, sizeof(sa_new));
    sa_new.sa_handler = segv_handler;
    sigemptyset(&sa_new.sa_mask);
    sa_new.sa_flags = 0;
    if (sigsetjmp(g_jmpbuf, 1) == 0) {
        sigaction(SIGSEGV, &sa_new, &sa_old);
        uint64_t val = *(volatile uint64_t *)addr;
        sigaction(SIGSEGV, &sa_old, NULL);
        return val;
    } else {
        sigaction(SIGSEGV, &sa_old, NULL);
        return 0xFFFFFFFFFFFFFFFF;
    }
}

static int check_lsplant_trampoline(void *ptr) {
    if (!ptr || (uintptr_t)ptr & 0x7) return 0;
    uint32_t *code = (uint32_t *)ptr;
    uint32_t instr0 = safe_read_u32(&code[0]);
    uint32_t instr1 = safe_read_u32(&code[1]);
    uint32_t instr2 = safe_read_u32(&code[2]);
    if (instr0 == 0xFFFFFFFF) return 0;
    if (instr0 == 0x58000060) {
        uint32_t instr1_msk = instr1 & ~(0xFF << 12);
        if (instr1_msk == 0xF8400010 && instr2 == 0xD61F0200) {
            uint64_t art_method_addr = safe_read_u64(&code[3]);
            if (art_method_addr != 0xFFFFFFFFFFFFFFFF && art_method_addr > 0x10000 && (art_method_addr & 0x7) == 0) {
                return 1;
            }
        }
    }
    return 0;
}

static int check_artmethod_trampoline(JNIEnv *env) {
    jclass executableCls = (*env)->FindClass(env, "java/lang/reflect/Executable");
    if (!executableCls) return 0;
    jfieldID artField = (*env)->GetFieldID(env, executableCls, "artMethod", "J");
    (*env)->DeleteLocalRef(env, executableCls);
    if (!artField) return 0;
    jclass cls = (*env)->FindClass(env, "java/lang/Thread");
    if (!cls) { (*env)->ExceptionClear(env); return 0; }
    jmethodID mid = (*env)->GetMethodID(env, cls, "dispatchUncaughtException", "(Ljava/lang/Throwable;)V");
    if (mid) {
        jobject methodObj = (*env)->ToReflectedMethod(env, cls, mid, JNI_FALSE);
        if (methodObj) {
            jlong artAddr = (*env)->GetLongField(env, methodObj, artField);
            (*env)->DeleteLocalRef(env, methodObj);
            if (artAddr != 0) {
                void **fields = (void **)(uintptr_t)(artAddr & 0x00000FFFFFFFFFFF);
                for (int k = 0; k < 8; k++) {
                    void *ptr = fields[k];
                    if ((uintptr_t)ptr > 0x10000 && ((uintptr_t)ptr & 0x7) == 0) {
                        if (check_lsplant_trampoline(ptr)) {
                            (*env)->DeleteLocalRef(env, cls);
                            return 1;
                        }
                    }
                }
            }
        } else {
            (*env)->ExceptionClear(env);
        }
    } else {
        (*env)->ExceptionClear(env);
    }
    (*env)->DeleteLocalRef(env, cls);
    return 0;
}

int check_lsposed_hook(JNIEnv *env) {
    int detected = 0;
    if (check_artmethod_trampoline(env)) detected = 1;
    if (check_dev_zero_deleted()) detected = 1;
    return detected;
}