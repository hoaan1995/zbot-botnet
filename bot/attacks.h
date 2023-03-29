#pragma once

#include "command.h"

#define ATTACKS_MAXPPS  2048
#define ATTACKS_MAXLEN  1400

struct attack_configuration {
    char target[32];
    char method[32];
    char payload[ATTACKS_MAXLEN];
    char srcip[256];
    uint16_t dest_port, duration;
    uint16_t repeat, rand, packet_len;
    uint16_t minpps, maxpps, pps;
    uint16_t maxlen, minlen;
} attack_config;

void attack_free(void);
void attack_init(void);
void attack_method_udpplain(struct attack_configuration *);
void attack_method_icmpecho(struct attack_configuration *);
void attack_method_tcpraw(struct attack_configuration *);
