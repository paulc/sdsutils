
#include "sdsutils.h"
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "blowfish.h"
#include "lzf.h"
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

int64_t sdsgetint(sds s,int len) {
    if (sdslen(s) < len) {
        return 0;
    }
    int64_t n = 0;
    s += len - 1;
    for (int i=0;i<len;i++) {
        n = (n << 8) + (unsigned char) *s--;
    }
    return n;
}

sds sdscatint(sds s,int64_t num, int len) {
    unsigned char c;
    for (int i=0;i<len;i++) {
        c = (unsigned char) ((num >> i*8) % 256);
        s = sdscatlen(s,&c,1);
    }
    return s;
}

sds sdscompress(sds s) {
    unsigned int out_len = sdslen(s);
    void *out = zmalloc(out_len);
    unsigned int n = lzf_compress(s,sdslen(s),out,out_len);
    sds d = NULL;
    if (n > 0) {
        d = sdsnewlen("lzf\0",4);
        d = sdscatlen(d,out,n);
    }
    zfree(out);
    return d;
}

sds sdsdecompress(sds s) {
    sds d = NULL;
    if (memcmp(s,"lzf\0",4) == 0) {
        unsigned int out_len = sdslen(s) * 10;
        void *out = zmalloc(out_len);
        unsigned int n = lzf_decompress(s+4,sdslen(s)-4,out,out_len);
        if (n > 0) {
            d = sdsnewlen(out,n);
        }
        zfree(out);
    }
    return d;
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

#define Z_N_LEN 4
#define Z_IV_LEN  8
#define Z_HDR_LEN 12

sds sdsencrypt(sds s,sds key,sds iv) {
    int pad = 0;
    blf_ctx c;
    blf_key(&c,(u_int8_t *)key,sdslen(key));
    while (sdslen(iv) < Z_IV_LEN) {
        sdscatlen(iv,"\x00",1);
    }
    sds z = sdsempty();
    z = sdscatint(z,sdslen(s),Z_N_LEN);
    z = sdscatlen(z,iv,Z_IV_LEN);
    z = sdscatlen(z,s,sdslen(s));
    while (((sdslen(z)-Z_HDR_LEN) % 8) != 0) {
        sdscatlen(z,"\x00",1);
        pad++;
    }
    blf_cbc_encrypt(&c,(u_int8_t *)iv,(u_int8_t *)z+Z_HDR_LEN,sdslen(s)+pad);
    return z;
}

sds sdsdecrypt(sds z,sds key) {
    if (sdslen(z) < Z_HDR_LEN) {
        return NULL;
    }
    int64_t len = sdsgetint(z,Z_N_LEN);
    sds iv = sdsnewlen(z+Z_N_LEN,Z_IV_LEN);
    blf_ctx c;
    blf_key(&c,(u_int8_t *)key,sdslen(key));
    sds s = sdsnewlen(z+Z_HDR_LEN,sdslen(z)-Z_HDR_LEN);
    if (sdslen(s) > 0) {
        blf_cbc_decrypt(&c,(u_int8_t *)iv,(u_int8_t *)s,sdslen(s));
        s = sdsrange(s,0,len-1);
    }
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

static int hexchr(unsigned char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    } else if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    } else if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    } else {
        return -1;
    }
}

sds sdsunhex(sds s) {
    sds r = sdsempty();
    int len = sdslen(s);
    int i = 0;
    unsigned char c;
    while (len - i > 0) {
        int x1 = hexchr(*(s+i));
        int x2 = hexchr(*(s+i+1));
        if (x1 == -1 || x2 == -1) {
            break;
        }
        c = x1 * 16 + x2;
        r = sdscatlen(r,&c,1);
        i += 2;
    }
    return r;
}

sds sdsunrepr(sds s) {
    sds r = sdsempty();
    int len = sdslen(s);
    unsigned char c;
    while(len-- > 0) {
        if (*s == '\\' && len > 0) {
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
                    c = 0;
                    for (int i=0;i<2;i++) {
                        s++; len--;
                        switch (*s) {
                            case '0': case '1': case '2': case '3': case '4':
                            case '5': case '6': case '7': case '8': case '9': 
                                c = (c << 4) + (*s - '0');
                                break;
                            case 'a': case 'b': case 'c': case 'd': case 'e': case 'f':
                                c = (c << 4) + (*s - 'a' + 10);
                                break;
                            case 'A': case 'B': case 'C': case 'D': case 'E': case 'F':
                                c = (c << 4) + (*s - 'A' + 10);
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

sds sdsexec(char *cmd) {
    FILE *fp = NULL;
    sds buf;
    if ((fp = popen(cmd,"r")) == NULL) {
        return NULL;
    }
    buf = sdsreadfile(fp);
    pclose(fp);
    return buf;
}

int pipeWrite(int fd, sds data) {
    FILE *f;
    int i;
    if ((f = fdopen(fd,"w")) == NULL) {
        return -1;
    }
    for (i = 0; i < sdslen(data); i++) {
        if (fputc(data[i],f) == EOF) {
            return -1;
        }
    }
    fclose(f);
    return i;
}

sds pipeRead(int fd) {
    FILE *f;
    char c;
    sds data = sdsempty();
    if ((f = fdopen(fd,"r")) == NULL) {
        return NULL;
    }
    while ((c = fgetc(f)) != EOF) {
        data = sdscatlen(data,&c,1);
    }
    fclose(f);
    return data;
}

sds sdspipe(char *cmd,sds input) {
    int p_in[2],p_out[2];
    pid_t pid;

    if (pipe(p_in) != 0 || pipe(p_out) != 0) {
        perror("Pipe failed");
        return NULL;
    }

    pid = fork();

    if (pid < 0) {
        perror("Fork failed");
        return NULL;
    } else if (pid == 0) {
        /* Child */
        dup2(p_in[0],0);
        dup2(p_out[1],1);
        close(p_in[0]);
        close(p_in[1]);
        close(p_out[0]);
        close(p_out[1]);
        execl("/bin/sh","sh","-c",cmd,NULL);
        perror("Exec failed");
        exit(255);
    } else {
        /* Parent */
        close(p_in[0]);
        close(p_out[1]);

        pid = fork();

        if (pid < 0) {
            perror("Fork failed");
            return NULL;
        } else if (pid == 0) {
            /* Child */
            close(p_out[0]);
            pipeWrite(p_in[1],input);
            close(p_in[1]);
            exit(0);
        } else {
            /* Parent */
            close(p_in[1]);
            sds out = pipeRead(p_out[0]);
            close(p_out[0]);
            return out;
        }
    }
    return NULL;
}
