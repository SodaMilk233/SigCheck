#ifndef UTILS_STRUTIL_H
#define UTILS_STRUTIL_H

#include <stddef.h>

int my_strcmp(const char* s1, const char* s2);
int my_strncmp(const char* s1, const char* s2, size_t n);
char* my_strstr(const char* haystack, const char* needle);
char* my_strchr(const char* s, int c);

#endif
