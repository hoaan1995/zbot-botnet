#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static char *xor_key = "qE6MGAbI";
static int key_len = 8;

char *util_random(size_t length)
{
    static char charset[] = "abcdefghijklmnopqrstuvwxyz";
    char *randomString = NULL;

    if (length)
    {
        randomString = malloc(sizeof(char) * (length +1));

        if (randomString)
        {
            for (int n = 0; n < length; n++)
            {
                int key = rand() % (int)(sizeof(charset) -1);
                randomString[n] = charset[key];
            }

            randomString[length] = '\0';
        }
    }

    return randomString;
}

void util_encode(char *string, int len)
{
    int i = 0;
    unsigned int tmp_key;

    for (i = 0; i < key_len; i++)
    {
        int q = 0;

        for (q = 0; q < len; q++)
            string[q] = string[q] ^ (xor_key[i] + q);
    }
}

char *util_replace(char *string, const char *substr, const char *replacement)
{
	char* tok = NULL;
	char* newstr = NULL;
	char* oldstr = NULL;
	int oldstr_len = 0;
	int substr_len = 0;
	int replacement_len = 0;

	newstr = strdup(string);
	substr_len = strlen(substr);
	replacement_len = strlen(replacement);

	if (substr == NULL || replacement == NULL)
		return newstr;

	while ((tok = strstr(newstr, substr)))
    {
		oldstr = newstr;
		oldstr_len = strlen(oldstr);
		newstr = (char *)malloc(sizeof(char)*(oldstr_len - substr_len + replacement_len + 1));

		if (newstr == NULL)
        {
			free(oldstr);
			return NULL;
		}

		memcpy(newstr, oldstr, tok - oldstr);
		memcpy(newstr + (tok - oldstr), replacement, replacement_len);
		memcpy(newstr + (tok - oldstr) + replacement_len, tok + substr_len, oldstr_len - substr_len - (tok - oldstr));
		memset(newstr + oldstr_len - substr_len + replacement_len, 0, 1);

		free(oldstr);
	}

	free(string);
	return newstr;
}

char *util_random_rg_ip(char *rg)
{
    char ip[17], *ptr_ip = ip;

    if (strcmp(rg, "ru") == 0)
    {
        switch (rand() % 5)
        {
            case 0: sprintf(ip, "5.3.%d.%d", rand() % 256, rand() % 256); break;
            case 1: sprintf(ip, "5.227.%d.%d", rand() % 256, rand() % 256); break;
            case 2: sprintf(ip, "5.228.%d.%d", rand() % 256, rand() % 256); break;
            case 3: sprintf(ip, "31.8.%d.%d", rand() % 256, rand() % 256); break;
            case 4: sprintf(ip, "31.23.%d.%d", rand() % 256, rand() % 256); break;
            case 5: sprintf(ip, "31.173.%d.%d", rand() % 256, rand() % 256); break;
        }
    }
    else if (strcmp(rg, "cn") == 0)
    {
        switch (rand() % 5)
        {
            case 0: sprintf(ip, "1.3.%d.%d", rand() % 256, rand() % 256); break;
            case 1: sprintf(ip, "1.8.%d.%d", rand() % 256, rand() % 256); break;
            case 2: sprintf(ip, "1.45.%d.%d", rand() % 256, rand() % 256); break;
            case 3: sprintf(ip, "1.50.%d.%d", rand() % 256, rand() % 256); break;
            case 4: sprintf(ip, "1.51.%d.%d", rand() % 256, rand() % 256); break;
            case 5: sprintf(ip, "1.118.%d.%d", rand() % 256, rand() % 256); break;
        }
    }
    else if (strcmp(rg, "us") == 0)
    {
        switch (rand() % 5)
        {
            case 0: sprintf(ip, "9.8.%d.%d", rand() % 256, rand() % 256); break;
            case 1: sprintf(ip, "15.160.%d.%d", rand() % 256, rand() % 256); break;
            case 2: sprintf(ip, "15.161.%d.%d", rand() % 256, rand() % 256); break;
            case 3: sprintf(ip, "15.168.%d.%d", rand() % 256, rand() % 256); break;
            case 4: sprintf(ip, "15.169.%d.%d", rand() % 256, rand() % 256); break;
            case 5: sprintf(ip, "15.172.%d.%d", rand() % 256, rand() % 256); break;
        }
    }
    else if (strcmp(rg, "kr") == 0)
    {
        switch (rand() % 5)
        {
            case 0: sprintf(ip, "1.11.%d.%d", rand() % 256, rand() % 256); break;
            case 1: sprintf(ip, "14.129.%d.%d", rand() % 256, rand() % 256); break;
            case 2: sprintf(ip, "14.138.%d.%d", rand() % 256, rand() % 256); break;
            case 3: sprintf(ip, "14.206.%d.%d", rand() % 256, rand() % 256); break;
            case 4: sprintf(ip, "27.1.%d.%d", rand() % 256, rand() % 256); break;
            case 5: sprintf(ip, "27.35.%d.%d", rand() % 256, rand() % 256); break;
        }
    }
    else
    {
        strcpy(ip, "null");
    }

    return ptr_ip;
}

void util_split_free(char **tokens, int count)
{
    int i = 0;

    for (i = 0; i < count; i++)
        free(tokens[i]);

    free(tokens);
}

int util_split(const char *txt, char delim, char ***tokens)
{
    int *tklen, *t, count = 1, in_quotes = 0;
    char **arr, *p = (char *) txt;

    while (*p != '\0')
    {
        char c_ptr = *p++;

        if (c_ptr == '"' && in_quotes == 0)
            in_quotes = 1;
        else if (c_ptr == '"' && in_quotes == 1)
            in_quotes = 0;

        if (c_ptr == delim && in_quotes == 0)
            count += 1;
    }

    in_quotes = 0;
    t = tklen = calloc(count, sizeof (int));
    for (p = (char *) txt; *p != '\0'; p++)
    {
        char c_ptr = *p;

        if (c_ptr == '"' && in_quotes == 0)
            in_quotes = 1;
        else if (c_ptr == '"' && in_quotes == 1)
            in_quotes = 0;

        if (c_ptr == delim && in_quotes == 0)
            *p == delim ? *t++ : (*t)++;
        else
            (*t)++;
    }

    in_quotes = 0;
    *tokens = arr = malloc(count * sizeof (char *));
    t = tklen;
    p = *arr++ = calloc(*(t++) + 1, sizeof (char *));

    while (*txt != '\0')
    {
        if (*txt == '"' && in_quotes == 0)
            in_quotes = 1;
        else if (*txt == '"' && in_quotes == 1)
            in_quotes = 0;

        if (*txt == delim && in_quotes == 0)
        {
            p = *arr++ = calloc(*(t++) + 1, sizeof (char *));
            txt++;
        }
        else
            *p++ = *txt++;
    }

    free(tklen);
    return count;
}
