#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <linux/prctl.h>
#include <linux/seccomp.h>
#include <sys/syscall.h>
#include "seccomp_check.h"
#include "utils/strutil.h"
#include "syscall.h"

static ssize_t read_file_by_syscall(const char* path, char* buf, size_t buf_size) {
    long fd = syscall_invoke(__NR_openat, AT_FDCWD, (long)path, O_RDONLY | O_CLOEXEC, 0, 0, 0);
    if (fd < 0) return -1;
    ssize_t total = 0;
    ssize_t bytes;
    while ((bytes = syscall_invoke(__NR_read, fd, (long)(buf + total), (long)(buf_size - total - 1), 0, 0, 0)) > 0) {
        total += bytes;
        if ((size_t)total >= buf_size - 1) break;
    }
    buf[total] = '\0';
    syscall_invoke(__NR_close, fd, 0, 0, 0, 0, 0);
    return total;
}

int check_seccomp_filter(void) {
    char buf[2048];
    ssize_t len = read_file_by_syscall("/proc/self/status", buf, sizeof(buf));
    if (len < 0) return 0;
    long seccomp_val = 0, nnp_proc = 0;
    char* p = my_strstr(buf, "Seccomp:");
    if (p) sscanf(p, "Seccomp:\t%ld", &seccomp_val);
    p = my_strstr(buf, "NoNewPrivs:");
    if (p) sscanf(p, "NoNewPrivs:\t%ld", &nnp_proc);
    long nnp_prctl = prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
    long mode_prctl = prctl(PR_GET_SECCOMP, 0, 0, 0, 0);
    if (seccomp_val == 2 && nnp_proc != nnp_prctl) return -1;
    if (seccomp_val == 2 && nnp_proc == 1 && nnp_prctl == 1) return -1;
    if (mode_prctl == 1) return -1;
    return 0;
}