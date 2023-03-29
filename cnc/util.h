#pragma once

char *util_random(int);
void util_encode(char *, int);
char *util_replace(char *, const char *, const char *);
char *util_random_rg_ip(char *);
void util_split_free(char **, int);
int util_split(const char *, char, char ***);
