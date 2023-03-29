#define _GNU_SOURCE

#ifdef DEBUG
#include <stdio.h>
#endif

#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>

#include "syscalls.h"
#include "util.h"

char *util_strcat(char *destination, const char *source)
{
    char *ptr = destination + util_strlen(destination);

    while (*source != '\0')
        *ptr++ = *source++;

    *ptr = '\0';
    return destination;
}

uint32_t util_local_addr(void)
{
    int fd;
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof (addr);

    if ((fd = syscalls_socket(AF_INET, SOCK_DGRAM, 0)) == -1)
    {
#ifdef DEBUG
        printf("[util] failed to resolv local addr\n");
#endif
        return 0;
    }

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INET_ADDR(8,8,8,8);
    addr.sin_port = htons(53);

    syscalls_connect(fd, &addr, sizeof (struct sockaddr_in));
    getsockname(fd, (struct sockaddr *)&addr, &addr_len);
    syscalls_close(fd);
    return addr.sin_addr.s_addr;
}

char *util_strstr(register char *string, char *substring)
{
    register char *a, *b;
    b = substring;
    if (*b == 0) {
	return string;
    }
    for ( ; *string != 0; string += 1) {
	if (*string != *b) {
	    continue;
	}
	a = string;
	while (1) {
	    if (*b == 0) {
		return string;
	    }
	    if (*a++ != *b++) {
		break;
	    }
	}
	b = substring;
    }
    return NULL;
}

void util_split_free(char **in, size_t num_elm)
{
    if (in == NULL)
        return;

    if (num_elm != 0)
        free(in[0]);

    free(in);
}

int util_strcpy(char *dst, char *src)
{
    int l = util_strlen(src);

    util_memcpy(dst, src, l + 1);

    return l;
}

char **util_split(char *in, size_t in_len, char delm, size_t *num_elm, size_t max)
{
    char *parsestr;
    char **out;
    size_t cnt = 1;
    size_t i;

    if (in == NULL || in_len == 0 || num_elm == NULL)
        return NULL;

    parsestr = malloc(in_len + 1);
    util_memcpy(parsestr, in, in_len + 1);
    parsestr[in_len] = '\0';

    *num_elm = 1;
    for (i=0; i < in_len; i++)
    {
        if (parsestr[i] == delm)
            (*num_elm)++;
        if (max > 0 && *num_elm == max)
            break;
    }

    out = malloc(*num_elm * sizeof(*out));
    out[0] = parsestr;
    for (i = 0; i<in_len && cnt<*num_elm; i++)
    {
        if (parsestr[i] != delm)
            continue;

        parsestr[i] = '\0';
        out[cnt] = parsestr + i + 1;
        cnt++;
    }

    return out;
}


int util_exists(char *buf, int buf_len, char *str, int str_len)
{
    int matches = 0;

    if (str_len > buf_len)
        return 0;

    while (buf_len--)
    {
        if (*buf++ == str[matches])
        {
            if (++matches == str_len)
                return 1;
        }
        else
            matches = 0;
    }

    return 0;
}

void util_memset(void *buf, int set, int len)
{
    char *zero = buf;
    while (len--)
        *zero++ = set;
}

int util_strlen(char *str)
{
    int c = 0;

    while (*str++ != 0)
        c++;
    return c;
}

int util_strcmp(char *str1, char *str2)
{
    int l1 = util_strlen(str1), l2 = util_strlen(str2);

    if (l1 != l2)
        return -1;

    while (l1--)
    {
        if (*str1++ != *str2++)
            return -1;
    }

    return 0;
}

void util_memcpy(void *dst, void *src, int len)
{
    char *r_dst = (char *)dst;
    char *r_src = (char *)src;
    while (len--)
        *r_dst++ = *r_src++;
}

char *util_itoa(int value, int radix, char *string)
{
    if (string == NULL)
        return NULL;

    if (value != 0)
    {
        char scratch[34];
        int neg;
        int offset;
        int c;
        unsigned int accum;

        offset = 32;
        scratch[33] = 0;

        if (radix == 10 && value < 0)
        {
            neg = 1;
            accum = -value;
        }
        else
        {
            neg = 0;
            accum = (unsigned int)value;
        }

        while (accum)
        {
            c = accum % radix;
            if (c < 10)
                c += '0';
            else
                c += 'A' - 10;

            scratch[offset] = c;
            accum /= radix;
            offset--;
        }

        if (neg)
            scratch[offset] = '-';
        else
            offset++;

        util_memcpy(string, &scratch[offset], util_strlen(&scratch[offset]));
    }
    else
    {
        string[0] = '0';
        string[1] = 0;
    }

    return string;
}
