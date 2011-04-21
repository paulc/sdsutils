
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "adlist.h"
#include "sds.h"
#include "sdsutils.h"

#define USAGE "Usage: readfile [-f <file>|-e <cmd>] [-o <file>] [-p <cmd>] [-n <count>] [-r|-u] [-c|-d] [-z|-Z] [-s] [-k <key>|-K <keyfile>]\n" \
              "       readfile [--long-options]\n" \
              "       readfile [-h|--help]\n" \
              "\n" \
              "       Read data from stdin & write to stdout (possibly transforming)\n"

#define HELP  "           -f,--file <file>        : Read from <file> rather than stdin\n" \
              "           -o,--out <file>         : Write to <file> rather than stdout\n" \
              "           -e,--exec <cmd>         : Read from <cmd> rather than stdin\n" \
              "           -p,--pipe <cmd>         : Pipe input through <cmd> (can specify multiple)\n" \
              "           -n,--count <count>      : Read <count> bytes from stdin|file\n" \
              "           -r,--repr               : Quote output using sdsrepr\n" \
              "           -u,--unrepr             : Unquote input using sdsunrepr\n" \
              "           -c,--compress           : Compress output using lzf\n" \
              "           -d,--decompress         : Decompress input using lzf\n" \
              "           -z,--encrypt            : Encrypt data\n" \
              "           -Z,--decrypt            : Decrypt data\n" \
              "           -k,--key <key>          : Key (unsafe)\n" \
              "           -K,--keyfile <keyfile>  : Read key from file\n" \
              "           -s,--digest             : Return digest (SHA256) of input data\n" \
              "           -h,--help               : Print help\n"

int main(int argc, char** argv) {

    FILE *in = stdin;
    FILE *out = stdout;
    int pipe = 0;
    list *pipe_cmd_list = NULL;
    int ch = 0;
    int repr = 0;
    int unrepr = 0;
    int sha256 = 0;
    int compress = 0;
    int decompress = 0;
    int encrypt = 0;
    int decrypt = 0;
    long n = 0;
    FILE *kf;
    sds data = NULL;
    sds key = NULL;

    static struct option longopts[] = {
        { "file",       required_argument,  NULL, 'f' },
        { "out",        required_argument,  NULL, 'o' },
        { "exec",       required_argument,  NULL, 'e' },
        { "pipe",       required_argument,  NULL, 'p' },
        { "count",      required_argument,  NULL, 'n' },
        { "repr",       no_argument,        NULL, 'r' },
        { "unrepr",     no_argument,        NULL, 'u' },
        { "compress",   no_argument,        NULL, 'c' },
        { "decompress", no_argument,        NULL, 'd' },
        { "encrypt",    no_argument,        NULL, 'z' },
        { "decrypt",    no_argument,        NULL, 'Z' },
        { "key",        required_argument,  NULL, 'k' },
        { "keyfile",    required_argument,  NULL, 'K' },
        { "digest",     no_argument,        NULL, 's' },
        { "help",       no_argument,        NULL, 'h' }
    };

    while ((ch = getopt_long(argc, argv, "f:o:e:n:p:rucdzZk:K:sh", longopts, NULL)) != -1) {
        switch(ch) {
            case 'f':
                if ((in = fopen(optarg,"r")) == NULL) {
                    perror("Error opening file");
                    exit(1);
                }
                break;
            case 'o':
                if ((out = fopen(optarg,"w")) == NULL) {
                    perror("Error opening file");
                    exit(1);
                }
                break;
            case 'e':
                if ((in = popen(optarg,"r")) == NULL) {
                    perror("Error executing command");
                    exit(1);
                }
                pipe = 1;
                break;
            case 'n':
                if ((n = strtol(optarg,(char **) NULL,10)) == 0) {
                    perror("Invalid value");
                    exit(1);
                }
                break;
            case 'p':
                if (pipe_cmd_list == NULL) {
                    pipe_cmd_list = listCreate();
                }
                listAddNodeTail(pipe_cmd_list,optarg);
                break;
            case 'r':
                repr = 1;
                break;
            case 'u':
                unrepr = 1;
                break;
            case 'c':
                compress = 1;
                break;
            case 'd':
                decompress = 1;
                break;
            case 'z':
                encrypt = 1;
                break;
            case 'Z':
                decrypt = 1;
                break;
            case 'k':
                key = sdsnew(optarg);
                break;
            case 'K':
                if ((kf = fopen(optarg,"r")) == NULL) {
                    perror("Unable to read keyfile");
                    exit(1);
                }
                if ((key = sdsreadfile(kf)) == NULL) {
                    perror("Unable to read keyfile");
                    sdsfree(key);
                    exit(1);
                }
                fclose(kf);
                break;
            case 's':
                sha256 = 1;
                break;
            case 'h':
                printf(USAGE);
                printf("\n");
                printf(HELP);
                printf("\n");
                exit(1);
        }
    }
    
    if ((encrypt || decrypt) && key == NULL) {
        char *k = getpass("Key: ");
        key = sdsnew(k);
    }

    /* Read data */

    if (n == 0) {
        data = sdsreadfile(in);
    } else {
        data = sdsread(in,n);
    }

    /* Input Filters */

    if (unrepr) {
        sds temp = sdsunrepr(data);
        sdsfree(data);
        data = temp;
    }

    if (decrypt) {
        sds temp = sdsdecrypt(data,key);
        sdsfree(data);
        data = temp;
    }

    if (decompress) {
        sds temp = sdsdecompress(data);
        if (temp != NULL) {
            sdsfree(data);
            data = temp;
        }
    }

    /* Pipe */

    if (pipe_cmd_list) {
        listNode *node;
        listIter *iter = listGetIterator(pipe_cmd_list,AL_START_HEAD);
        while ((node = listNext(iter)) != NULL) {
            sds temp = sdspipe((char *)listNodeValue(node),data);
            sdsfree(temp);
            /*
            if (temp != NULL) {
                sdsfree(data);
                data = temp;
            } else {
                printf("Pipe failed\n");
            }
            */
        } 
        listReleaseIterator(iter);
        listRelease(pipe_cmd_list);
    }

    /* Output Filters */

    if (compress) {
        sds temp = sdscompress(data);
        if (temp != NULL) {
            sdsfree(data);
            data = temp;
        }
    }

    if (encrypt) {
        FILE *random;
        if ((random = fopen("/dev/urandom","r")) == NULL) {
            perror("Error opening /dev/urandom");
            exit(1);
        }
        sds iv = sdsread(random,8);
        if (iv == NULL || sdslen(iv) != 8) {
            fprintf(stderr,"Error reading IV\n");
            exit(1);
        }
        sds temp = sdsencrypt(data,key,iv);
        sdsfree(iv);
        sdsfree(data);
        data = temp;
    } 

    if (sha256) {
        sds digest = sdssha256(data);
        sdsprinthex(out,"SHA256: ",digest,"\n");
        sdsfree(digest);
    } else if (repr) {
        sdsprintrepr(out,"",data,"");
    } else {
        fwrite(data,1,sdslen(data),out);
    }

    /* Clean-ip */

    (pipe == 0) ? fclose(in) : pclose(in);
    sdsfree(data);
    sdsfree(key);
    exit(0);
}
