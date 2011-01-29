
#include "sdsutils.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "blowfish.h"
#include "sds.h"
#include "slre.h"
#include "zmalloc.h"

int char_count(char *s, char c) {
    int count = 0;
    while (*s) {
        if (*s == c) {
            count += 1;
        }
        s++;
    }
    return count;
}
int sdscount(sds s,char c) {
	int len = sdslen(s), count = 0; 
    for (int j = 0; j < len; j++) {
		if (s[j] == c) 
			count++;
	}
	return count;
}

sds sdsencrypt(sds s,sds key,sds iv) {
    int len = sdslen(s);
    int pad = 0;
    blf_ctx c;
    blf_key(&c,(u_int8_t *)key,sdslen(key));
    while (sdslen(iv) < 8) {
        sdscatlen(iv,"\x00",1);
    }
    sds z = sdsempty();
    z = sdscatprintf(z,"%08d",len);
    z = sdscatlen(z,iv,8);
    z = sdscatlen(z,s,sdslen(s));
    while ((sdslen(z) % 8) != 0) {
        sdscatlen(z,"\x00",1);
        pad++;
    }
    blf_cbc_encrypt(&c,(u_int8_t *)iv,(u_int8_t *)z+16,sdslen(s)+pad);
    return z;
}

sds sdsdecrypt(sds z,sds key) {
    char len_f[9];
    u_int8_t iv[8];
    if (sdslen(z) < 24) {
        return sdsempty();
    }
    blf_ctx c;
    blf_key(&c,(u_int8_t *)key,sdslen(key));
    memset(len_f,0,9);
    strncpy(len_f,z,8);
    memcpy(iv,z+8,8);
    sds s = sdsnewlen(z+16,sdslen(z)-16);
    int len = strtol(len_f,(char **)NULL,10);
    blf_cbc_decrypt(&c,iv,(u_int8_t *)s,sdslen(s));
    s = sdsrange(s,0,len-1);
    return s;
}

sds sdsread(FILE *fp,size_t nbyte) {
    int n;
    size_t count = 0;
    char buf[1024];
    sds data = sdsempty();
    while (nbyte - count > 0) {
        int nread = (nbyte - count) > 1024 ? 1024 : (nbyte - count);
        n = read(fileno(fp),buf,nread);
        if (n == -1) {
            return NULL;
        }
        data = sdscatlen(data,buf,n);
        count += n;
    }
    return data;
}

sds sdsreadfile(FILE *fp) {
	int n;
    char buf[1024];
    sds data = sdsempty();
    while ((n = read(fileno(fp),buf,1024)) != 0) {
        if (n == -1) {
            return NULL;
        }
        data = sdscatlen(data,buf,n);
    }
    return data;
}

sds sdsreaddelim(FILE *fp,char *delim,int len) {
    char c;
    int count = 0;
    sds line = sdsempty();
    while ((c = fgetc(fp)) != EOF) {
        line = sdscatlen(line,&c,1);
        count++;
        if (count >= len) {
            if (memcmp(delim,line+count-len,len) == 0) {
                line = (count == len) ? sdscpylen(line,"",0) : sdsrange(line,0,count-len-1);
                break;
            }
        }
    }
    return line;
}

sds sdsreadline(FILE *fp,const char *prompt) {
    char c;
    sds line = sdsempty();
	if (isatty(fileno(fp))) {
		fputs(prompt,stdout);
	}
    while ((c = fgetc(fp)) != EOF && c != '\n') {
        line = sdscatlen(line,&c,1);
    }
    return line;
}

sds *sdsmatchre(sds s,struct slre *slre,int ncap,int *count) {
    int slots = 5, elements = 0;
    sds *matches = zmalloc(sizeof(sds)*slots);
	struct cap *cap = zcalloc(sizeof(struct cap) * ncap);
    if (slre_match(slre,s,sdslen(s),cap)) {
        for (int i=0; i < ncap; i++) {
            if (cap[i].len > 0) {
                if (slots < elements+1) {
                    slots *= 2;
                    sds *newmatches = zrealloc(matches,sizeof(sds)*slots);
                    matches = newmatches;
                }
                matches[elements++] = sdsnewlen(cap[i].ptr,cap[i].len);
            }
        }
    }
    zfree(cap);
    *count = elements;
    return matches;
}

sds *sdsmatch(sds s,char *re,int *count) {
	struct slre slre;
	if (slre_compile(&slre,re) != 1) {
        return NULL;
	}
    int ncap = char_count(re,'(')+1;
    return sdsmatchre(s,&slre,ncap,count);
}

void sdsfreematchres(sds* matches,int count) {
    if (!matches) return;
    while(count--)
        sdsfree(matches[count]);
    zfree(matches);
}

void sdsrepr(FILE *fp,char *prefix,sds s,char *suffix) {
    sds m = sdsempty();
    m = sdscatrepr(m,s,sdslen(s));
    fputs(prefix,fp);
    fputs(m,fp);
    fputs(suffix,fp);
    sdsfree(m);
}

