#pragma once

#include <netinet/in.h>

int syscalls_socket(int, int, int);
int syscalls_read(int, void *, int);
int syscalls_write(int, void *, int);
int syscalls_connect(int, struct sockaddr_in *, int);
int syscalls_open(char *, int, int);
int syscalls_close(int);
void syscalls_exit(int);
pid_t syscalls_fork(void);
