#pragma once

int admin_login_mysql(char *, char *);
int admin_create_and_bind(char *);
void admin_init(void);
void *admin_listen(void *);
