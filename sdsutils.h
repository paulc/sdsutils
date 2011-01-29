
#ifndef _SDSUTILS_H
#define _SDSUTILS_H

#include "sds.h"
#include "slre.h"

#include <stdio.h>

int char_count(char *s, char c);
int sdscount(sds s,char c);
sds sdsread(FILE *fp,size_t nbyte);
sds sdsreadfile(FILE *fp);
sds sdsreaddelim(FILE *fp,char *delim,int len);
sds sdsreadline(FILE *fp,const char *prompt);
sds *sdsmatchre(sds s,struct slre *slre,int ncap,int *count);
sds *sdsmatch(sds s,char *re,int *count);
sds sdsencrypt(sds s,sds key,sds iv);
sds sdsdecrypt(sds z,sds key);
void sdsfreematchres(sds* matches,int count);
void sdsrepr(FILE *fp,char *prefix,sds s,char *suffix);

#endif /* _SDSUTILS_H */
