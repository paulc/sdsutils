
#include "sdsutils.h"
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "blowfish.h"
#include "sds.h"
#include "sha256.h"
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

int sdsstartswith(sds s,sds prefix) {
    int l1 = sdslen(s);
    int l2 = sdslen(prefix);
    if (l1 < l2) {
        return 0;
    }
    return (memcmp(s,prefix,l2) == 0);
}

int sdscount(sds s,char c) {
	int len = sdslen(s), count = 0; 
    for (int j = 0; j < len; j++) {
		if (s[j] == c) 
			count++;
	}
	return count;
}

int64_t sdsgetint64(sds s) {
    if (sdslen(s) != 8) {
        return 0;
    }
    int64_t n = 0;
    s += 7;
    for (int i=0;i<8;i++) {
        n = (n << 8) + (unsigned char) *s--;
    }
    return n;
}

sds sdscatint64(sds s,int64_t l) {
    unsigned char c;
    for (int i=0;i<8;i++) {
        c = (unsigned char) ((l >> i*8) % 256);
        s = sdscatlen(s,&c,1);
    }
    return s;
}

sds sdssha256(sds s) {
    context_sha256_t c;
    uint8_t digest[32];
    sha256_starts(&c);
    sha256_update(&c,(uint8_t *) s,(uint32_t) sdslen(s));
    sha256_finish(&c,digest);
    sds d = sdsnewlen(digest,32);
    return d;
}

sds sdsencrypt(sds s,sds key,sds iv) {
    int pad = 0;
    blf_ctx c;
    blf_key(&c,(u_int8_t *)key,sdslen(key));
    while (sdslen(iv) < 8) {
        sdscatlen(iv,"\x00",1);
    }
    sds z = sdsempty();
    z = sdscatint64(z,sdslen(s));
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
    if (sdslen(z) < 24) {
        return sdsempty();
    }
    sds len_f = sdsnewlen(z,8);
    sds iv = sdsnewlen(z+8,8);
    int64_t len = sdsgetint64(len_f);
    blf_ctx c;
    blf_key(&c,(u_int8_t *)key,sdslen(key));
    sds s = sdsnewlen(z+16,sdslen(z)-16);
    blf_cbc_decrypt(&c,(u_int8_t *)iv,(u_int8_t *)s,sdslen(s));
    s = sdsrange(s,0,len-1);
    sdsfree(len_f);
    sdsfree(iv);
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
        if (n == 0) {
            break;
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

sds sdshex(sds s) {
    sds r = sdsempty();
    int len = sdslen(s);
    while(len--) {
        r = sdscatprintf(r,"%02x",(unsigned char)*s++);
    }
    return r;
}

sds sdsunrepr(sds s) {
    sds r = sdsempty();
    int len = sdslen(s);
    unsigned char c;
    while(len--) {
        if (*s == '\\') {
            s++; len--;
            switch (*s) {
                case '\\': r = sdscatlen(r,"\\",1); break;        
                case '"':  r = sdscatlen(r,"\"",1); break;        
                case 'n':  r = sdscatlen(r,"\n",1); break;
                case 'r':  r = sdscatlen(r,"\r",1); break;
                case 't':  r = sdscatlen(r,"\t",1); break;
                case 'a':  r = sdscatlen(r,"\a",1); break;
                case 'b':  r = sdscatlen(r,"\b",1); break;
                case 'x':  
                    for (int i=0;i<2;i++) {
                        c = 0;
                        s++; len--;
                        switch (*s) {
                            case '0': case '1': case '2': case '3': case '4':
                            case '5': case '6': case '7': case '8': case '9': 
                                c += (*s - '0') << (i * 4);
                                break;
                            case 'a': case 'b': case 'c': case 'd': case 'e': case 'f':
                                c += (*s - 'a' + 10) << (i * 4);
                                break;
                            case 'A': case 'B': case 'C': case 'D': case 'E': case 'F':
                                c += (*s - 'a' + 10) << (i * 4);
                                break;
                        }
                    }
                    r = sdscatlen(r,&c,1);
                    break;
            }
        } else {
            r = sdscatlen(r,s,1);
        }
        s++;
    }
    return r;
}

sds sdsrepr(sds s) {
    sds r = sdsempty();
    int len = sdslen(s);
    while(len--) {
        switch(*s) {
            case '\\':
            case '"':
                r = sdscatprintf(r,"\\%c",*s);
                break;
            case '\n': r = sdscatlen(r,"\\n",2); break;
            case '\r': r = sdscatlen(r,"\\r",2); break;
            case '\t': r = sdscatlen(r,"\\t",2); break;
            case '\a': r = sdscatlen(r,"\\a",2); break;
            case '\b': r = sdscatlen(r,"\\b",2); break;
            default:
                if (isprint(*s))
                    r = sdscatprintf(r,"%c",*s);
                else
                    r = sdscatprintf(r,"\\x%02x",(unsigned char)*s);
                break;
        }
        s++;
    }
    return r;
}

void sdsprintrepr(FILE *fp,char *prefix,sds s,char *suffix) {
    sds m = sdsrepr(s);
    fputs(prefix,fp);
    fputs(m,fp);
    fputs(suffix,fp);
    sdsfree(m);
}

void sdsprinthex(FILE *fp,char *prefix,sds s,char *suffix) {
    sds m = sdshex(s);
    fputs(prefix,fp);
    fputs(m,fp);
    fputs(suffix,fp);
    sdsfree(m);
}
