#pragma once

#include <stdint.h>

#if BYTE_ORDER == BIG_ENDIAN
#define HTONS(n) (n)
#define HTONL(n) (n)
#elif BYTE_ORDER == LITTLE_ENDIAN
#define HTONS(n) (((((unsigned short)(n) & 0xff)) << 8) | (((unsigned short)(n) & 0xff00) >> 8))
#define HTONL(n) (((((unsigned long)(n) & 0xff)) << 24) | ((((unsigned long)(n) & 0xff00)) << 8) | ((((unsigned long)(n) & 0xff0000)) >> 8) | ((((unsigned long)(n) & 0xff000000)) >> 24))
#else
#error
#endif

#ifdef __ARM_EABI__
#define SCN(n) ((n) & 0xfffff)
#else
#define SCN(n) (n)
#endif

#define INET_ADDR(o1,o2,o3,o4) (HTONL((o1 << 24) | (o2 << 16) | (o3 << 8) | (o4 << 0)))

char *util_strcat(char *, const char *);
int util_strcpy(char *, char *);
uint32_t util_local_addr(void);
char *util_strstr(register char *, char *);
int util_exists(char *, int, char *, int);
void util_memset(void *, int, int);
int util_strlen(char *);
int util_strcmp(char *, char *);
void util_memcpy(void *, void *, int);
void util_split_free(char **, size_t);
char **util_split(char *, size_t, char, size_t *, size_t);
char *util_itoa(int, int, char *);
