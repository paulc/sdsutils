
#ifndef _SDSUTILS_H
#define _SDSUTILS_H

#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>

#include "adlist.h"
#include "blowfish.h"
#include "lzf.h"
#include "sds.h"
#include "sha256.h"
#include "slre.h"
#include "zmalloc.h"

int char_count(char *s, char c);
int sdscount(sds s,char c);
int sdsstartswith(sds s,sds prefix);
int64_t sdsgetint(sds s,int len);
sds sdscatint(sds s,int64_t num,int len);
sds sdsread(FILE *fp,size_t nbyte);
sds sdsreadfile(FILE *fp);
sds sdsreaddelim(FILE *fp,void *delim,int len);
sds sdsreadline(FILE *fp,const char *prompt);
list *sdsmatchre(sds s,struct slre *slre,int ncap);
list *sdsmatch(sds s,char *re);
sds sdssha256(sds s);
sds sdscompress(sds s);
sds sdsdecompress(sds s);
sds sdsencrypt(sds s,sds key,sds iv);
sds sdsdecrypt(sds z,sds key);
sds sdshex(sds s);
sds sdsunhex(sds s);
sds sdsrepr(sds s);
sds sdsunrepr(sds s);
void sdsprintrepr(FILE *fp,char *prefix,sds s,char *suffix);
void sdsprinthex(FILE *fp,char *prefix,sds s,char *suffix);
sds sdsexec(char *cmd);
sds sdspipe(char *cmd,sds input);
list *sdssplit(sds s,sds delim);
sds listJoin(list *l,sds delim);
list *listMap(list *l,void *(*f)(listNode *node),void (*free)(void *ptr));
list *listMapWithState(list *l,void *(*f)(listNode *node,void *state),
                               void (*free)(void *ptr),void *state);
void listApply(list *l,void *(*f)(listNode *node));


#endif /* _SDSUTILS_H */
