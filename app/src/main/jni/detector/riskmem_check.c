#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <asm/unistd.h>
#include "riskmem_check.h"
#include "utils/strutil.h"
#include "syscall.h"

static const char* const excluded_regions[] = {
    "[vdso]", "[sigpage]", "[vsyscall]", "[anon:linker_alloc]"
};

static int region_excluded(const char* pathname) {
    for (size_t i = 0; i < sizeof(excluded_regions) / sizeof(excluded_regions[0]); i++) {
        if (my_strcmp(pathname, excluded_regions[i]) == 0) return 1;
    }
    return 0;
}

static int check_maps_line(const char* line, char* buf_out, size_t buf_size) {
    char perm[5] = {0};
    char pathname[256] = {0};
    char addr_range[64] = {0};
    if (sscanf(line, "%63s %4s %*x %*x:%*x %*d %255s", addr_range, perm, pathname) < 2) {
        return 0;
    }
    if (region_excluded(pathname)) return 0;
    if (perm[0] != 'r' || perm[3] != 'p') return 0;
    int has_w = (perm[1] == 'w');
    int has_x = (perm[2] == 'x');
    if (has_w && has_x) {
        if (my_strstr(pathname, "bytehook-plt-trampolines") != NULL) {
            snprintf(buf_out, buf_size, "地址: %s\n权限: %s\n类型: Hook框架\n路径: ByteHook trampoline", addr_range, perm);
            return 1;
        }
        if (pathname[0] == '\0' || my_strcmp(pathname, "[anon]") == 0) {
            snprintf(buf_out, buf_size, "类型: 可疑匿名映射\n地址: %s\n权限: %s\n路径: %s", addr_range, perm, pathname[0] == '\0' ? "[匿名内存-无路径]" : pathname);
            return 1;
        }
    }
    if (has_x && my_strcmp(pathname, "[anon:.bss]") == 0) {
        snprintf(buf_out, buf_size, "地址: %s\n权限: %s\n路径: %s", addr_range, perm, pathname);
        return 1;
    }
    return 0;
}

const char* check_suspicious_maps(char* buf_out, size_t buf_size) {
    long fd = syscall_invoke(__NR_openat, AT_FDCWD, (long)"/proc/self/maps", O_RDONLY, 0, 0, 0);
    if (fd < 0) return NULL;
    char buf[4096];
    size_t buf_len = 0;
    long bytes;
    const char* result = NULL;
    while ((bytes = syscall_invoke(__NR_read, fd, (long)(buf + buf_len), sizeof(buf) - buf_len - 1, 0, 0, 0)) > 0) {
        buf_len += bytes;
        buf[buf_len] = '\0';
        char* line_start = buf;
        char* line_end;
        while ((line_end = my_strchr(line_start, '\n')) != NULL) {
            *line_end = '\0';
            if (check_maps_line(line_start, buf_out, buf_size)) {
                result = buf_out;
                break;
            }
            line_start = line_end + 1;
        }
        if (result) break;
        if (line_start < buf + buf_len) {
            size_t remaining = buf + buf_len - line_start;
            memmove(buf, line_start, remaining);
            buf_len = remaining;
        } else {
            buf_len = 0;
        }
    }
    if (!result && buf_len > 0) {
        buf[buf_len] = '\0';
        if (check_maps_line(buf, buf_out, buf_size)) {
            result = buf_out;
        }
    }
    syscall_invoke(__NR_close, fd, 0, 0, 0, 0, 0);
    return result;
}