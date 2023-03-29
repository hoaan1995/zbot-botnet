#pragma once

#include <stdint.h>

#define TOR_MAX_SOCKS   20

struct sock_value {
    uint32_t ip_val;
    uint16_t port_val;
};

uint32_t tor_retrieve_addr(int);
uint16_t tor_retrieve_port(int);
void tor_socks_init(void);
