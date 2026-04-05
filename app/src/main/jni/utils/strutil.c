#include "strutil.h"

int my_strcmp(const char* s1, const char* s2) {
    while (*s1 && (*s1 == *s2)) { s1++; s2++; }
    return *(unsigned char*)s1 - *(unsigned char*)s2;
}

int my_strncmp(const char* s1, const char* s2, size_t n) {
    if (n == 0) return 0;
    if (!s1 || !s2) {
        if (!s1 && !s2) return 0;
        return s1 ? 1 : -1;
    }
    const unsigned char* p1 = (const unsigned char*)s1;
    const unsigned char* p2 = (const unsigned char*)s2;
    while (n--) {
        if (*p1 != *p2) return *p1 - *p2;
        if (*p1 == '\0') return 0;
        p1++;
        p2++;
    }
    return 0;
}

char* my_strstr(const char* haystack, const char* needle) {
    if (!haystack || !needle) return NULL;
    if (*needle == '\0') return (char*)haystack;
    size_t nlen = 0;
    while (needle[nlen]) nlen++;
    unsigned char first = (unsigned char)needle[0];
    const unsigned char* h = (const unsigned char*)haystack;
    const unsigned char* n = (const unsigned char*)needle;
    while (*h) {
        if (*h == first) {
            size_t i;
            for (i = 1; i < nlen; i++) {
                if (h[i] != n[i]) break;
            }
            if (i == nlen) return (char*)h;
        }
        h++;
    }
    return NULL;
}

char* my_strchr(const char* s, int c) {
    if (!s) return NULL;
    unsigned char uc = (unsigned char)c;
    const unsigned char* p = (const unsigned char*)s;
    while (*p) {
        if (*p == uc) return (char*)p;
        p++;
    }
    if (uc == '\0') return (char*)p;
    return NULL;
}
