
#ifndef _SDSUTILS_H
#define _SDSUTILS_H

#include "sds.h"
#include "slre.h"

#include <stdio.h>
#include <stdint.h>

int char_count(char *s, char c);
int sdscount(sds s,char c);
int64_t sdsgetint64(sds s);
sds sdscatint64(sds s,int64_t l);
sds sdsread(FILE *fp,size_t nbyte);
sds sdsreadfile(FILE *fp);
sds sdsreaddelim(FILE *fp,char *delim,int len);
sds sdsreadline(FILE *fp,const char *prompt);
sds *sdsmatchre(sds s,struct slre *slre,int ncap,int *count);
sds *sdsmatch(sds s,char *re,int *count);
sds sdssha256(sds s);
sds sdsencrypt(sds s,sds key,sds iv);
sds sdsdecrypt(sds z,sds key);
void sdsfreematchres(sds* matches,int count);
sds sdshex(sds s);
sds sdsrepr(sds s);
void sdsprintrepr(FILE *fp,char *prefix,sds s,char *suffix);
void sdsprinthex(FILE *fp,char *prefix,sds s,char *suffix);

#endif /* _SDSUTILS_H */
