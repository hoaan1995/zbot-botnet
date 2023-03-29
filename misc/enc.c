#include <stdio.h>
#include <unistd.h>
#include <string.h>

static char *xor_key = "qE6MGAbI"; // the bigger it is, more rounds (more cpu to decode)
static int key_len = 8; // length of xor_key
static unsigned int fake_key = 0xDEADBEEF; // mirai key

void xor_encode(char *string, int len)
{
    int i = 0;
    unsigned int tmp_key;

    for (i = 0; i < key_len; i++)
    {
        int q = 0;

        if (i % 2 == 0)
            tmp_key = tmp_key + fake_key;

        tmp_key = tmp_key >> 16;
        tmp_key = tmp_key & 0x0000FFFF;

        for (q = 0; q < len; q++)
            string[q] = string[q] ^ (xor_key[i] + q);
    }
}

void xor_decode(char *string, int len)
{
    int i = 0;
    unsigned int tmp_key;

    for (i = 0; i < key_len; i++)
    {
        int q = 0;

        if (i % 2 == 0)
            tmp_key = tmp_key + fake_key;

        tmp_key = tmp_key >> 16;
        tmp_key = tmp_key & 0x0000FFFF;

        for (q = len; q != -1; q--)
            string[q] = string[q] ^ (xor_key[i] + q);
    }
}

int main(int argc, char const *argv[])
{
    if (argc != 2)
    {
        printf("Must supply a string to enc\n");
        return 0;
    }

    int i;
    char string[strlen(argv[1]) + 1];
    strcpy(string, argv[1]);
    string[strlen(argv[1]) + 1] = '\0';

    xor_encode(string, strlen(argv[1]) + 1);
    for (i = 0; i < strlen(argv[1]) + 1; i++)
        printf("\\x%02X", ((unsigned char *)string)[i]);

    printf(" (%d)\nDecoded: ", (int)strlen(argv[1]) + 1);
    xor_decode(string, strlen(argv[1]) + 1);
    printf("%s\n", string);

    return 0;
}
