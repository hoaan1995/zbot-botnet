#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/syscall.h>
#include <stdarg.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "util.h"

int syscalls_socket(int domain, int type, int protocol)
{
#if defined(__NR_socketcall)
    struct {
        int domain, type, protocol;
    } socketcall;

    socketcall.domain = domain;
    socketcall.type = type;
    socketcall.protocol = protocol;

    int ret = syscall(SCN(SYS_socketcall), 1, &socketcall);
    return ret;
#else
    return syscall(SCN(SYS_socket), domain, type, protocol);
#endif
}

int syscalls_read(int fd, void *buf, int len)
{
    return syscall(SCN(SYS_read), fd, buf, len);
}

int syscalls_write(int fd, void *buf, int len)
{
    return syscall(SCN(SYS_write), fd, buf, len);
}

int syscalls_connect(int fd, struct sockaddr_in *addr, int len)
{
#if defined(__NR_socketcall)
    struct {
        int fd;
        struct sockaddr_in *addr;
        int len;
    } socketcall;

    socketcall.fd = fd;
    socketcall.addr = addr;
    socketcall.len = len;

    int ret = syscall(SCN(SYS_socketcall), 3, &socketcall);
    return ret;
#else
    return syscall(SCN(SYS_connect), fd, addr, len);
#endif
}

int syscalls_open(char *path, int flags, int other)
{
    return syscall(SCN(SYS_open), path, flags, other);
}

int syscalls_close(int fd)
{
    return syscall(SCN(SYS_close), fd);
}

void syscalls_exit(int code)
{
    syscall(SCN(SYS_exit), code);
}

pid_t syscalls_fork(void)
{
    return syscall(SCN(SYS_fork));
}
