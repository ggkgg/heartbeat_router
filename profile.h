#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#define KEYVALLEN 100 


char * l_trim(char * szOutput, const char *szInput); 
char *r_trim(char *szOutput, const char *szInput);
char * a_trim(char * szOutput, const char * szInput);
int GetProfileString(const char *profile, char *AppName, char *KeyName, char *KeyVal );

