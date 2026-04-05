#include "memutil.h"

void* memory_alloc(size_t size) {
    void* ptr = malloc(size);
    if (ptr) {
        memory_zero(ptr, size);
    }
    return ptr;
}

void memory_free(void *ptr, size_t len) {
    if (ptr) {
        memory_zero(ptr, len);
        free(ptr);
    }
}

void memory_zero(void *ptr, size_t len) {
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (len--) {
        *p++ = 0;
    }
}

void* memory_copy(void* dest, const void* src, size_t n) {
    if (!dest || !src) return NULL;
    unsigned char* d = (unsigned char*)dest;
    const unsigned char* s = (const unsigned char*)src;
    while (n--) {
        *d++ = *s++;
    }
    return dest;
}

void* memory_set(void* s, int c, size_t n) {
    if (!s) return NULL;
    unsigned char* p = (unsigned char*)s;
    while (n--) {
        *p++ = (unsigned char)c;
    }
    return s;
}

int memory_compare(const void* s1, const void* s2, size_t n) {
    if (!s1 || !s2) return -1;
    const unsigned char* p1 = (const unsigned char*)s1;
    const unsigned char* p2 = (const unsigned char*)s2;
    while (n--) {
        if (*p1 != *p2) {
            return *p1 - *p2;
        }
        p1++;
        p2++;
    }
    return 0;
}

void* my_memmem(const void *haystack, size_t haystack_len, const void *needle, size_t needle_len) {
    if (!haystack || !needle || haystack_len < needle_len) return NULL;
    const char *h = (const char *)haystack;
    const char *n = (const char *)needle;
    for (size_t i = 0; i <= haystack_len - needle_len; i++) {
        if (memory_compare(h + i, n, needle_len) == 0) {
            return (void *)(h + i);
        }
    }
    return NULL;
}