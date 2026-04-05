#include "pkginfo.h"
#include "binder.h"
#include "parcel.h"
#include "utils/memutil.h"
#include "utils/strutil.h"
#include "utils/sysutil.h"
#include "syscall.h"
#include <asm/unistd.h>
#include <fcntl.h>
#include <string.h>

#define GET_SIGNATURES 0x0000000000000040ULL
#define GET_SIGNING_CERTIFICATES 0x0000000008000000ULL
#define VAL_PARCELABLE 4
#define VAL_STRING 4
#define VAL_INT 4
#define VAL_LONG 8
#define MAX_SIGNATURE_LEN (1 << 20)

static int is_valid_der(const uint8_t* p, size_t len) {
    if (len < 16 || p[0] != 0x30) return 0;
    size_t total = 0;
    if (p[1] == 0x82 && len >= 4) {
        total = 4 + (size_t)((uint16_t)p[2] << 8 | (uint16_t)p[3]);
    } else if (p[1] == 0x81 && len >= 3) {
        total = 3 + (size_t)p[2];
    } else if (p[1] < 0x80) {
        total = 2 + (size_t)p[1];
    } else {
        return 0;
    }
    if (total != len) return 0;
    static const uint8_t oid_rsa[] = {0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01};
    static const uint8_t oid_ec[]  = {0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01};
    static const uint8_t oid_ed[]  = {0x06, 0x03, 0x2b, 0x65, 0x70};
    static const uint8_t oid_dsa[] = {0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x38, 0x04, 0x01};
    for (size_t k = 0; k + sizeof(oid_rsa) <= len; ++k) {
        if (memory_compare(p + k, oid_rsa, sizeof(oid_rsa)) == 0 ||
            memory_compare(p + k, oid_ec, sizeof(oid_ec)) == 0 ||
            memory_compare(p + k, oid_ed, sizeof(oid_ed)) == 0 ||
            memory_compare(p + k, oid_dsa, sizeof(oid_dsa)) == 0) {
            return 1;
        }
    }
    return 0;
}

static int find_cert_in_signing_details(const uint8_t* data, size_t size, const uint8_t** cert, size_t* len) {
    for (size_t i = 0; i + 16 < size; i += 4) {
        int32_t arr_len;
        memory_copy(&arr_len, data + i, 4);
        if (arr_len < 1 || arr_len > 16) continue;
        int32_t presence;
        memory_copy(&presence, data + i + 4, 4);
        if (presence != 1) continue;
        int32_t cert_len;
        memory_copy(&cert_len, data + i + 8, 4);
        if (cert_len < 128 || cert_len > MAX_SIGNATURE_LEN) continue;
        if (i + 12 + (size_t)cert_len > size) continue;
        const uint8_t* p = data + i + 12;
        if (is_valid_der(p, (size_t)cert_len)) {
            *cert = p;
            *len = (size_t)cert_len;
            return 1;
        }
    }
    return 0;
}

static int find_cert_in_signatures_array(const uint8_t* data, size_t size, const uint8_t** cert, size_t* len) {
    for (size_t i = 0; i + 12 < size; i += 4) {
        int32_t arr_len;
        memory_copy(&arr_len, data + i, 4);
        if (arr_len < 1 || arr_len > 16) continue;
        int32_t presence;
        memory_copy(&presence, data + i + 4, 4);
        if (presence != 1) continue;
        int32_t cert_len;
        memory_copy(&cert_len, data + i + 8, 4);
        if (cert_len < 128 || cert_len > MAX_SIGNATURE_LEN) continue;
        if (i + 12 + (size_t)cert_len > size) continue;
        const uint8_t* p = data + i + 12;
        if (is_valid_der(p, (size_t)cert_len)) {
            *cert = p;
            *len = (size_t)cert_len;
            return 1;
        }
    }
    return 0;
}

static int find_cert_by_pattern(const uint8_t* data, size_t size, const uint8_t** cert, size_t* len) {
    for (size_t i = 0; i + 4 < size; i += 4) {
        int32_t maybe_len;
        memory_copy(&maybe_len, data + i, 4);
        if (maybe_len < 128 || maybe_len > MAX_SIGNATURE_LEN) continue;
        if (i + 4 + (size_t)maybe_len > size) continue;
        const uint8_t* p = data + i + 4;
        if (is_valid_der(p, (size_t)maybe_len)) {
            *cert = p;
            *len = (size_t)maybe_len;
            return 1;
        }
    }
    return 0;
}

static int find_cert(const uint8_t* data, size_t size, const uint8_t** cert, size_t* len) {
    if (size < 16) return 0;
    int sdk = android_get_version();
    if (sdk >= 33) {
        if (find_cert_in_signing_details(data, size, cert, len)) return 1;
        if (find_cert_in_signatures_array(data, size, cert, len)) return 1;
        if (find_cert_by_pattern(data, size, cert, len)) return 1;
    } else {
        if (find_cert_in_signatures_array(data, size, cert, len)) return 1;
        if (find_cert_in_signing_details(data, size, cert, len)) return 1;
        if (find_cert_by_pattern(data, size, cert, len)) return 1;
    }

    return 0;
}

static int get_package_name(char* buf, size_t size) {
    if (size == 0) return -1;
    buf[0] = '\0';
    int fd = (int)syscall_invoke(__NR_openat, AT_FDCWD, (long)"/proc/self/cmdline", O_RDONLY, 0, 0, 0);
    if (fd >= 0) {
        long n = syscall_invoke(__NR_read, fd, (long)buf, (long)size - 1, 0, 0, 0);
        syscall_invoke(__NR_close, fd, 0, 0, 0, 0, 0);
        if (n > 0) {
            buf[n] = '\0';
            for (size_t i = 0; i < (size_t)n && buf[i]; ++i) {
                if (buf[i] == ':') { buf[i] = '\0'; break; }
            }
            for (size_t i = 0; i < (size_t)n && buf[i]; ++i) {
                if (buf[i] == '.') return 0;
            }
        }
    }
    fd = (int)syscall_invoke(__NR_openat, AT_FDCWD, (long)"/proc/self/maps", O_RDONLY, 0, 0, 0);
    if (fd < 0) return -1;
    char line[4096];
    long bytes;
    int found = 0;
    int offset = 0;
    char leftover[1024] = {0};
    while (!found) {
        bytes = syscall_invoke(__NR_read, fd, (long)line + offset, sizeof(line) - offset - 1, 0, 0, 0);
        if (bytes <= 0) break;
        bytes += offset;
        line[bytes] = '\0';
        char* line_start = line;
        char* line_end;
        while ((line_end = my_strchr(line_start, '\n')) != NULL) {
            *line_end = '\0';
            char* apk_pos = NULL;
            char* search_start = line_start;
            while ((apk_pos = my_strstr(search_start, "base.apk")) != NULL ||
                   (apk_pos = my_strstr(search_start, "split_")) != NULL) {
                char* path_start = my_strchr(line_start, '/');
                                    if (path_start) {
                                    char* path_end = my_strchr(path_start, '\n');                    if (path_end) *path_end = '\0';
                    if (my_strncmp(path_start, "/data/app/", 10) == 0) {
                        char* pkg_start = path_start + 10;
                        char* pkg_end = my_strchr(pkg_start, '-');
                        if (!pkg_end) pkg_end = my_strchr(pkg_start, '/');
                        if (pkg_end && pkg_end > pkg_start) {
                            size_t pkg_len = pkg_end - pkg_start;
                            if (pkg_len < size) {
                                memcpy(buf, pkg_start, pkg_len);
                                buf[pkg_len] = '\0';
                                found = 1;
                                goto done;
                            }
                        }
                    }
                }
                search_start = apk_pos + 1;
                if (search_start >= line_end) break;
            }
            line_start = line_end + 1;
        }
        if (found) break;
        if (line_start > line) {
            offset = bytes - (line_start - line);
            if (offset > 0 && offset < (int)sizeof(leftover)) {
                memory_copy(leftover, line_start, offset);
                memory_copy(line, leftover, offset);
                line[offset] = '\0';
            } else {
                offset = 0;
            }
        } else {
            offset = 0;
        }
    }
done:
    syscall_invoke(__NR_close, fd, 0, 0, 0, 0, 0);
    return found ? 0 : -1;
}

static int get_user_id(void) {
    return (int)(syscall_invoke(__NR_getuid, 0, 0, 0, 0, 0, 0) / 100000U);
}

static unsigned char* do_get_signature(int fd, uint32_t handle, const char* pkg, size_t* len) {
    int sdk = android_get_version();
    ParcelBuilder pb;
    parcel_init(&pb);
    parcel_writeInterfaceToken(&pb, "android.content.pm.IPackageManager");
    parcel_writeString16(&pb, pkg);
    uint32_t flags;
    if (sdk >= 29) {
        flags = GET_SIGNING_CERTIFICATES;
    } else {
        flags = GET_SIGNATURES;
    }
    if (sdk >= 33) {
        parcel_writeInt64(&pb, (int64_t)flags);
    } else {
        parcel_writeInt32(&pb, (int32_t)flags);
    }
    parcel_writeInt32(&pb, get_user_id());
    const void* rbuf = NULL;
    size_t rsz = 0;
    const void* roffs = NULL;
    size_t rosz = 0;
    uint32_t transact_code = (sdk < 23) ? 2 : 3;
    int ret = binder_transact(fd, handle, transact_code, pb.buf, pb.size, &rbuf, &rsz, &roffs, &rosz);
    parcel_free(&pb);
    if (ret != 0) {
        return NULL;
    }
    const uint8_t* cert = NULL;
    size_t clen = 0;
    unsigned char* result = NULL;
    if (find_cert(rbuf, rsz, &cert, &clen)) {
        result = memory_alloc(clen);
        if (result) {
            memory_copy(result, cert, clen);
            *len = clen;
        }
    }
    free_binder_buffer(fd, rbuf);
    if (result != NULL) {
        return result;
    }
    if (sdk >= 33 && result == NULL) {
        ParcelBuilder pb2;
        parcel_init(&pb2);
        parcel_writeInterfaceToken(&pb2, "android.content.pm.IPackageManager");
        parcel_writeVersionedPackage(&pb2, pkg, -1);
        parcel_writeInt64(&pb2, (int64_t)flags);
        parcel_writeInt32(&pb2, get_user_id());
        ret = binder_transact(fd, handle, 4, pb2.buf, pb2.size, &rbuf, &rsz, &roffs, &rosz);
        parcel_free(&pb2);
        if (ret == 0) {
            if (find_cert(rbuf, rsz, &cert, &clen)) {
                result = memory_alloc(clen);
                if (result) {
                    memory_copy(result, cert, clen);
                    *len = clen;
                }
            }
            free_binder_buffer(fd, rbuf);
        }
    }
    return result;
}

unsigned char* get_signature_from_binder(size_t* len) {
    if (!len) {
        return NULL;
    }
    *len = 0;
    char pkg[256];
    if (get_package_name(pkg, sizeof(pkg)) != 0) {
        return NULL;
    }
    int fd = get_binder_driver_fd();
    if (fd < 0) {
        return NULL;
    }
    uint32_t handle = 0;
    if (get_binder_service_handle(fd, "package", &handle) != 0) {
        return NULL;
    }
    return do_get_signature(fd, handle, pkg, len);
}