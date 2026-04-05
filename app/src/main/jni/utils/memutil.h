#ifndef UTILS_MEMUTIL_H
#define UTILS_MEMUTIL_H

#include <stdlib.h>

void* memory_alloc(size_t size);
void memory_free(void *ptr, size_t len);
void memory_zero(void *ptr, size_t len);
void* memory_copy(void* dest, const void* src, size_t n);
void* memory_set(void* s, int c, size_t n);
int memory_compare(const void* s1, const void* s2, size_t n);
void* my_memmem(const void *haystack, size_t haystack_len, const void *needle, size_t needle_len);

#define my_memcmp memory_compare

#endif
