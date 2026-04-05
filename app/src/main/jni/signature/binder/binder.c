#include "binder.h"
#include "parcel.h"
#include "utils/memutil.h"
#include "utils/strutil.h"
#include "syscall.h"
#include <linux/android/binder.h>
#include <asm/unistd.h>
#include <fcntl.h>
#include <stdint.h>

struct linux_dirent64 {
    uint64_t d_ino;
    int64_t d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[];
};

#ifndef DT_LNK
#define DT_LNK 10
#endif

static const char* const get_binder_paths[] = {
    "/dev/binder",
    "/dev/binderfs/binder",
    "/dev/hwbinder",
};

static const int get_binder_path_count = sizeof(get_binder_paths) / sizeof(get_binder_paths[0]);

static int open_binder_device(void) {
    for (int i = 0; i < get_binder_path_count; i++) {
        int fd = (int)syscall_invoke(__NR_openat, AT_FDCWD, (long)get_binder_paths[i], O_RDWR, 0, 0, 0);
        if (fd >= 0) {
            struct binder_version ver;
            memory_set(&ver, 0, sizeof(ver));
            if (syscall_invoke(__NR_ioctl, fd, BINDER_VERSION, (long)&ver, 0, 0, 0) >= 0) {
                return fd;
            }
            syscall_invoke(__NR_close, fd, 0, 0, 0, 0, 0);
        }
    }
    return -1;
}

static int find_binder_fd(void) {
    uint64_t pid = (uint64_t)syscall_invoke(__NR_getpid, 0, 0, 0, 0, 0, 0);
    char path[64];
    char num[22];
    int nlen = 0;
    {
        uint64_t x = pid;
        char tmp[22];
        int t = 0;
        if (x == 0) tmp[t++] = '0';
        while (x > 0) {
            tmp[t++] = (char)('0' + (x % 10));
            x /= 10;
        }
        for (int i = 0; i < t; i++) {
            num[i] = tmp[t - 1 - i];
        }
        nlen = t;
        num[nlen] = '\0';
    }
    size_t pos = 0;
    const char* p = "/proc/";
    while (*p) path[pos++] = *p++;
    for (int i = 0; i < nlen; ++i) path[pos++] = num[i];
    p = "/fd";
    while (*p) path[pos++] = *p++;
    path[pos] = '\0';
    int dir_fd = (int)syscall_invoke(__NR_openat, AT_FDCWD, (long)path, O_RDONLY | O_DIRECTORY, 0, 0, 0);
    if (dir_fd < 0) return -1;
    char buf[1024];
    int best = -1;
    for (;;) {
        long nread = (long)syscall_invoke(__NR_getdents64, dir_fd, (long)buf, sizeof(buf), 0, 0, 0);
        if (nread <= 0) break;
        for (long bpos = 0; bpos <= nread - (long)sizeof(struct linux_dirent64); ) {
            struct linux_dirent64* d = (struct linux_dirent64*)(buf + bpos);
            if (d->d_reclen == 0 || bpos + d->d_reclen > nread) break;
            if (d->d_type == DT_LNK) {
                char link[256];
                long len = (long)syscall_invoke(__NR_readlinkat, dir_fd, (long)d->d_name, (long)link, sizeof(link) - 1, 0, 0);
                if (len > 0) {
                    link[len] = '\0';
                    if (my_strstr(link, "/dev/binder") != NULL) {
                        int fd_num = 0;
                        for (int i = 0; d->d_name[i] >= '0' && d->d_name[i] <= '9'; ++i) {
                            fd_num = fd_num * 10 + (d->d_name[i] - '0');
                        }
                        best = fd_num;
                        goto done;
                    }
                }
            }
            bpos += d->d_reclen;
        }
    }
done:
    syscall_invoke(__NR_close, dir_fd, 0, 0, 0, 0, 0);
    return best;
}

int get_binder_driver_fd(void) {
    int fd = find_binder_fd();
    if (fd >= 0) {
        struct binder_version ver;
        memory_set(&ver, 0, sizeof(ver));
        if (syscall_invoke(__NR_ioctl, fd, BINDER_VERSION, (long)&ver, 0, 0, 0) >= 0) {
            return fd;
        }
    }
    fd = open_binder_device();
    if (fd >= 0) {
        return fd;
    }
    return -1;
}

static int do_transact(int fd, uint32_t handle, uint32_t code, const void* payload, size_t payload_size, const void** out_buf, size_t* out_size, const void** out_offs, size_t* out_offs_size) {
    struct { uint32_t cmd; struct binder_transaction_data tr; } __attribute__((packed)) w;
    memory_set(&w, 0, sizeof(w));
    w.cmd = BC_TRANSACTION;
    w.tr.target.handle = handle;
    w.tr.code = code;
    w.tr.flags = TF_ACCEPT_FDS;
    w.tr.data_size = payload_size;
    w.tr.offsets_size = 0;
    w.tr.data.ptr.buffer = (binder_uintptr_t)payload;
    uint8_t rbuf[32768];
    struct binder_write_read bwr;
    memory_set(&bwr, 0, sizeof(bwr));
    bwr.write_size = sizeof(w);
    bwr.write_buffer = (binder_uintptr_t)&w;
    bwr.read_size = sizeof(rbuf);
    bwr.read_buffer = (binder_uintptr_t)rbuf;
    int retry = 0;
    for (;;) {
        long ret = syscall_invoke(__NR_ioctl, fd, BINDER_WRITE_READ, (long)&bwr, 0, 0, 0);
        if (ret < 0) return -1;
        size_t off = 0;
        while (off + sizeof(uint32_t) <= bwr.read_consumed) {
            uint32_t cmd;
            memory_copy(&cmd, rbuf + off, sizeof(cmd));
            off += sizeof(cmd);
            switch (cmd) {
                case BR_NOOP:
                case BR_SPAWN_LOOPER:
                case BR_OK:
                case BR_TRANSACTION_PENDING_FROZEN:
                case BR_TRANSACTION_COMPLETE:
                    break;
                case BR_REPLY: {
                    if (off + sizeof(struct binder_transaction_data) > bwr.read_consumed) return -1;
                    struct binder_transaction_data tr;
                    memory_copy(&tr, rbuf + off, sizeof(tr));
                    *out_buf = (const void*)(uintptr_t)tr.data.ptr.buffer;
                    *out_size = tr.data_size;
                    *out_offs = (const void*)(uintptr_t)tr.data.ptr.offsets;
                    *out_offs_size = tr.offsets_size;
                    return 0;
                }
                case BR_FAILED_REPLY:
                case BR_DEAD_REPLY:
                case BR_FROZEN_REPLY:
                    return -1;
                case BR_TRANSACTION:
                    off += sizeof(struct binder_transaction_data);
                    break;
                default:
                    return -1;
            }
        }
        if (++retry > 5) return -1;
        bwr.write_size = 0;
        bwr.read_size = sizeof(rbuf);
        bwr.read_consumed = 0;
    }
}

int free_binder_buffer(int fd, const void* buffer) {
    struct { uint32_t cmd; binder_uintptr_t ptr; } __attribute__((packed)) w;
    w.cmd = BC_FREE_BUFFER;
    w.ptr = (binder_uintptr_t)buffer;
    struct binder_write_read bwr;
    memory_set(&bwr, 0, sizeof(bwr));
    bwr.write_size = sizeof(w);
    bwr.write_buffer = (binder_uintptr_t)&w;
    return syscall_invoke(__NR_ioctl, fd, BINDER_WRITE_READ, (long)&bwr, 0, 0, 0) < 0 ? -1 : 0;
}

int get_binder_service_handle(int fd, const char* name, uint32_t* handle) {
    ParcelBuilder pb;
    parcel_init(&pb);
    parcel_writeInterfaceToken(&pb, "android.os.IServiceManager");
    parcel_writeString16(&pb, name);
    const void* rbuf = NULL;
    size_t rsz = 0;
    const void* roffs = NULL;
    size_t rosz = 0;
    int ret = do_transact(fd, 0, 2, pb.buf, pb.size, &rbuf, &rsz, &roffs, &rosz);
    if (ret != 0) {
        ret = do_transact(fd, 0, 1, pb.buf, pb.size, &rbuf, &rsz, &roffs, &rosz);
    }
    parcel_free(&pb);
    if (ret != 0) return -1;
    if (rosz >= sizeof(binder_size_t)) {
        binder_size_t off0;
        memory_copy(&off0, roffs, sizeof(off0));
        if ((size_t)off0 + sizeof(struct flat_binder_object) <= rsz) {
            const struct flat_binder_object* fbo = (const struct flat_binder_object*)((const uint8_t*)rbuf + off0);
            if (fbo->hdr.type == BINDER_TYPE_HANDLE || fbo->hdr.type == BINDER_TYPE_WEAK_HANDLE) {
                *handle = fbo->handle;
                free_binder_buffer(fd, rbuf);
                return 0;
            }
        }
    }
    free_binder_buffer(fd, rbuf);
    return -1;
}

int binder_transact(int fd, uint32_t handle, uint32_t code, const void* payload, size_t payload_size, const void** reply_data, size_t* reply_size, const void** reply_offsets, size_t* reply_offsets_size) {
    return do_transact(fd, handle, code, payload, payload_size, reply_data, reply_size, reply_offsets, reply_offsets_size);
}