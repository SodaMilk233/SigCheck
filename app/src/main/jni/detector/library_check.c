#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <errno.h>
#include <asm/unistd.h>
#include "library_check.h"
#include "utils/memutil.h"
#include "utils/strutil.h"
#include "syscall.h"

typedef struct {
    void *start;
    void *end;
    char perm[5];
    off_t offset;
    char pathname[256];
} MapItem;

typedef struct {
    size_t count;
    MapItem *items;
} ProcMaps;

static uint32_t crc32_table[256];
static int crc32_inited = 0;

static uint32_t crc32_checksum(const uint8_t *data, size_t len) {
    if (!crc32_inited) {
        for (int i = 0; i < 256; i++) {
            unsigned int v = i;
            for (int j = 8; j > 0; j--) v = (v & 1) ? ((v >> 1) ^ 0x82F63B78) : (v >> 1);
            crc32_table[i] = v;
        }
        crc32_inited = 1;
    }
    uint32_t crc = 0xDEADBEEF;
    for (size_t i = 0; i < len; i++) {
        unsigned char b = data[i] ^ 0xA5;
        crc = ((crc >> 7) ^ crc32_table[(crc ^ b) & 0xFF]) ^ 0xA5A5A5A5;
    }
    return ~crc;
}

static ProcMaps proc_maps_new() {
    ProcMaps maps = {0, NULL};
    long fd = syscall_invoke(__NR_openat, AT_FDCWD, (long)"/proc/self/maps", O_RDONLY, 0, 0, 0);
    if (fd < 0) return maps;
    maps.items = (MapItem *)malloc(sizeof(MapItem) * 64);
    if (!maps.items) {
        syscall_invoke(__NR_close, fd, 0, 0, 0, 0, 0);
        return maps;
    }
    size_t capacity = 64;
    char line_assembly_buffer[4096];
    size_t data_in_line_buffer = 0;
    char temp_read_buffer[1024];
    long bytes_read;
    int eof_reached = 0;
    while (!eof_reached) {
        size_t space_to_fill = 4096 - data_in_line_buffer - 1;
        if (space_to_fill == 0 && data_in_line_buffer > 0) {
            syscall_invoke(__NR_close, fd, 0, 0, 0, 0, 0);
            free(maps.items);
            maps.items = NULL;
            maps.count = 0;
            return maps;
        }
        size_t read_len = (space_to_fill > 1024) ? 1024 : space_to_fill;
        if (read_len == 0 && !eof_reached) {
            syscall_invoke(__NR_close, fd, 0, 0, 0, 0, 0);
            free(maps.items);
            maps.items = NULL;
            maps.count = 0;
            return maps;
        }
        bytes_read = syscall_invoke(__NR_read, fd, (long)temp_read_buffer, (long)read_len, 0, 0, 0);
        if (bytes_read < 0) {
            syscall_invoke(__NR_close, fd, 0, 0, 0, 0, 0);
            free(maps.items);
            maps.items = NULL;
            maps.count = 0;
            return maps;
        }
        if (bytes_read == 0) eof_reached = 1;
        if (bytes_read > 0) {
            memcpy(line_assembly_buffer + data_in_line_buffer, temp_read_buffer, bytes_read);
            data_in_line_buffer += bytes_read;
        }
        line_assembly_buffer[data_in_line_buffer] = '\0';
        char *current_line_start = line_assembly_buffer;
        char *next_line_ptr;
        char *effective_data_end = line_assembly_buffer + data_in_line_buffer;
        while (current_line_start < effective_data_end && (next_line_ptr = my_strchr(current_line_start, '\n'))) {
            if (next_line_ptr >= effective_data_end) break;
            *next_line_ptr = '\0';
            if (maps.count >= capacity) {
                capacity *= 2;
                MapItem *new_items = (MapItem *)realloc(maps.items, sizeof(MapItem) * capacity);
                if (!new_items) {
                    syscall_invoke(__NR_close, fd, 0, 0, 0, 0, 0);
                    free(maps.items);
                    maps.items = NULL;
                    maps.count = 0;
                    return maps;
                }
                maps.items = new_items;
            }
            MapItem *item = &maps.items[maps.count];
            unsigned long map_offset;
            if (sscanf(current_line_start, "%p-%p %4s %lx %*x:%*x %*d %255s", &item->start, &item->end, item->perm, &map_offset, item->pathname) == 5) {
                item->offset = (off_t)map_offset;
                maps.count++;
            }
            current_line_start = next_line_ptr + 1;
        }
        if (current_line_start < effective_data_end && current_line_start > line_assembly_buffer) {
            size_t remaining_chars = effective_data_end - current_line_start;
            memmove(line_assembly_buffer, current_line_start, remaining_chars);
            data_in_line_buffer = remaining_chars;
            line_assembly_buffer[data_in_line_buffer] = '\0';
        } else if (current_line_start >= effective_data_end) data_in_line_buffer = 0;
    }
    if (data_in_line_buffer > 0) {
        line_assembly_buffer[data_in_line_buffer] = '\0';
        if (maps.count >= capacity) {
            capacity *= 2;
            MapItem *new_items = (MapItem *)realloc(maps.items, sizeof(MapItem) * capacity);
            if (!new_items) {
                syscall_invoke(__NR_close, fd, 0, 0, 0, 0, 0);
                free(maps.items);
                maps.items = NULL;
                maps.count = 0;
                return maps;
            }
            maps.items = new_items;
        }
        MapItem *item = &maps.items[maps.count];
        unsigned long map_offset;
        if (sscanf(line_assembly_buffer, "%p-%p %4s %lx %*x:%*x %*d %255s", &item->start, &item->end, item->perm, &map_offset, item->pathname) == 5) {
            item->offset = (off_t)map_offset;
            maps.count++;
        }
    }
    syscall_invoke(__NR_close, fd, 0, 0, 0, 0, 0);
    return maps;
}

static void proc_maps_free(ProcMaps *maps) {
    if (maps->items) free(maps->items);
    maps->items = NULL;
    maps->count = 0;
}

int check_library_integrity(const char* lib_name) {
    if (!lib_name) return -1;
    ProcMaps maps = proc_maps_new();
    if (maps.count == 0) {
        if (maps.items) proc_maps_free(&maps);
        return -1;
    }
    int result = -1;
    for (size_t i = 0; i < maps.count; i++) {
        MapItem *m = &maps.items[i];
        if (my_strstr(m->pathname, lib_name) && my_strstr(m->perm, "x")) {
            long fd = syscall_invoke(__NR_openat, AT_FDCWD, (long)m->pathname, O_RDONLY, 0, 0, 0);
            if (fd < 0) {
                result = -1;
                goto cleanup;
            }
            unsigned char ehdr[64];
            if (syscall_invoke(__NR_read, fd, (long)ehdr, 64, 0, 0, 0) != 64) {
                syscall_invoke(__NR_close, fd, 0, 0, 0, 0, 0);
                result = -1;
                goto cleanup;
            }
            uint64_t phoff64;
            uint16_t phentsize;
            uint16_t phnum;
            if (ehdr[4] == 2) {
                memcpy(&phoff64, ehdr + 32, 8);
                memcpy(&phentsize, ehdr + 54, 2);
                memcpy(&phnum, ehdr + 56, 2);
            } else {
                uint32_t phoff32;
                memcpy(&phoff32, ehdr + 28, 4);
                phoff64 = phoff32;
                memcpy(&phentsize, ehdr + 42, 2);
                memcpy(&phnum, ehdr + 44, 2);
            }
            uint32_t phoff = (uint32_t)phoff64;
            size_t phdr_table_size = (size_t)phentsize * phnum;
            unsigned char *phdr_table = (unsigned char *)malloc(phdr_table_size);
            if (!phdr_table) {
                syscall_invoke(__NR_close, fd, 0, 0, 0, 0, 0);
                result = -1;
                goto cleanup;
            }
            if (syscall_invoke(__NR_lseek, fd, phoff, SEEK_SET, 0, 0, 0) < 0) {
                free(phdr_table);
                syscall_invoke(__NR_close, fd, 0, 0, 0, 0, 0);
                result = -1;
                goto cleanup;
            }
            if (syscall_invoke(__NR_read, fd, (long)phdr_table, (long)phdr_table_size, 0, 0, 0) != (long)phdr_table_size) {
                free(phdr_table);
                syscall_invoke(__NR_close, fd, 0, 0, 0, 0, 0);
                result = -1;
                goto cleanup;
            }
            size_t exec_size = 0;
            off_t exec_offset = 0;
            int is_elf64 = (ehdr[4] == 2);
            for (int j = 0; j < phnum; j++) {
                unsigned char *phdr = phdr_table + j * phentsize;
                uint32_t p_type;
                uint32_t p_flags;
                uint64_t p_memsz, p_offset;
                if (is_elf64) {
                    p_type = *((uint32_t*)(phdr + 0));
                    p_flags = *((uint32_t*)(phdr + 4));
                    p_offset = *((uint64_t*)(phdr + 8));
                    p_memsz = *((uint64_t*)(phdr + 40));
                } else {
                    p_type = *((uint32_t*)(phdr + 0));
                    p_offset = *((uint32_t*)(phdr + 4));
                    p_memsz = *((uint32_t*)(phdr + 20));
                    p_flags = *((uint32_t*)(phdr + 24));
                }
                if (p_type == 1 && (p_flags & 1) && p_offset == (uint64_t)m->offset) {
                    exec_size = (size_t)p_memsz;
                    exec_offset = (off_t)p_offset;
                    break;
                }
            }
            free(phdr_table);
            if (exec_size == 0) {
                syscall_invoke(__NR_close, fd, 0, 0, 0, 0, 0);
                result = -1;
                goto cleanup;
            }
            if (syscall_invoke(__NR_lseek, fd, exec_offset, SEEK_SET, 0, 0, 0) < 0) {
                syscall_invoke(__NR_close, fd, 0, 0, 0, 0, 0);
                result = -1;
                goto cleanup;
            }
            void *file_data = malloc(exec_size);
            if (!file_data) {
                syscall_invoke(__NR_close, fd, 0, 0, 0, 0, 0);
                result = -1;
                goto cleanup;
            }
            long bytes_read = 0;
            size_t total_read = 0;
            while (total_read < exec_size) {
                bytes_read = syscall_invoke(__NR_read, fd, (long)((char*)file_data + total_read),
                                           (long)(exec_size - total_read), 0, 0, 0);
                if (bytes_read <= 0) {
                    free(file_data);
                    syscall_invoke(__NR_close, fd, 0, 0, 0, 0, 0);
                    result = -1;
                    goto cleanup;
                }
                total_read += bytes_read;
            }
            syscall_invoke(__NR_close, fd, 0, 0, 0, 0, 0);
            syscall_invoke(__NR_mprotect, (long)m->start, (long)exec_size, PROT_READ | PROT_EXEC, 0, 0, 0);
            uint32_t file_crc = crc32_checksum((const uint8_t *)file_data, exec_size);
            uint32_t mem_crc = crc32_checksum((const uint8_t *)m->start, exec_size);
            free(file_data);
            result = (file_crc != mem_crc) ? 1 : 0;
            goto cleanup;
        }
    }
cleanup:
    proc_maps_free(&maps);
    return result;
}