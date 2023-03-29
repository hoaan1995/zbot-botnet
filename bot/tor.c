#define _GNU_SOURCE

#ifdef DEBUG
#include <stdio.h>
#endif

#include <stdint.h>
#include <stdlib.h>

#include "tor.h"
#include "util.h"

struct sock_value socks[TOR_MAX_SOCKS];

uint32_t tor_retrieve_addr(int id)
{
    if (socks[id].ip_val > 0)
        return socks[id].ip_val;
}

uint16_t tor_retrieve_port(int id)
{
    if (socks[id].port_val  > 0)
        return socks[id].port_val;
}

void tor_add_sock(int id, uint32_t ip_val, uint16_t port_val)
{
    socks[id].ip_val = ip_val;
    socks[id].port_val = port_val;
}

void tor_socks_init(void)
{
    tor_add_sock(0, INET_ADDR(45,82,176,194), HTONS(9034));
    tor_add_sock(1, INET_ADDR(91,236,251,131), HTONS(9217));
    tor_add_sock(2, INET_ADDR(18,177,13,247), HTONS(443));
    tor_add_sock(3, INET_ADDR(62,109,8,218), HTONS(8888));
    tor_add_sock(4, INET_ADDR(82,99,213,98), HTONS(9191));
    tor_add_sock(5, INET_ADDR(35,225,55,174), HTONS(9251));
    tor_add_sock(6, INET_ADDR(194,99,22,206), HTONS(9050));
    tor_add_sock(7, INET_ADDR(45,147,199,142), HTONS(8060));
    tor_add_sock(8, INET_ADDR(47,104,188,20), HTONS(8999));
    tor_add_sock(9, INET_ADDR(54,149,179,115), HTONS(9050));
    tor_add_sock(10, INET_ADDR(195,128,102,178), HTONS(9050));
    tor_add_sock(11, INET_ADDR(185,176,25,66), HTONS(9002));
    tor_add_sock(12, INET_ADDR(54,188,106,141), HTONS(9080));
    tor_add_sock(13, INET_ADDR(193,47,35,56), HTONS(10000));
    tor_add_sock(14, INET_ADDR(88,193,137,205), HTONS(9050));
    tor_add_sock(15, INET_ADDR(134,209,84,21), HTONS(9119));
    tor_add_sock(16, INET_ADDR(194,58,111,244), HTONS(9050));
    tor_add_sock(17, INET_ADDR(192,99,161,66), HTONS(9050));
    tor_add_sock(18, INET_ADDR(193,47,35,53), HTONS(9090));
    tor_add_sock(19, INET_ADDR(167,179,74,97), HTONS(9251));
    tor_add_sock(20, INET_ADDR(185,30,228,141), HTONS(9050));
}
