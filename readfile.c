
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sds.h"
#include "sdsutils.h"

#define USAGE "Usage: readfile [-f <file>|-e <cmd>] [-p <cmd>] [-n <count>] [-r|-u] [-c|-d] [-z|-Z] [-s] [-k <key>|-K <keyfile>]\n" \
              "       readfile [--long-options]\n" \
              "       readfile [-h|--help]\n" \
              "\n" \
              "       Read data from stdin & write to stdout (possibly transforming)\n"

#define HELP  "           -f,--file <file>        : Read from <file> rather than stdin\n" \
              "           -e,--exec <cmd>         : Read from <cmd> rather than stdin\n" \
              "           -p,--pipe <cmd>         : Pipe input through <cmd>\n" \
              "           -n,--count <count>      : Read <count> bytes from stdin|file\n" \
              "           -r,--repr               : Quote output using sdsrepr\n" \
              "           -u,--unrepr             : Unquote input using sdsunrepr\n" \
              "           -c,--compress           : Compress output using lzf\n" \
              "           -d,--decompress         : Decompress input using lzf\n" \
              "           -e,--encrypt            : Encrypt data\n" \
              "           -d,--decrypt            : Decrypt data\n" \
              "           -k,--key <key>          : Key (unsafe)\n" \
              "           -K,--keyfile <keyfile>  : Read key from file\n" \
              "           -s,--digest             : Return digest (SHA256) of input data\n" \
              "           -h,--help               : Print help\n"

int main(int argc, char** argv) {

    FILE *f = stdin;
    int pipe = 0;
    char *pipe_cmd = NULL;
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

    while ((ch = getopt_long(argc, argv, "f:e:n:p:rucdzZk:K:sh", longopts, NULL)) != -1) {
        switch(ch) {
            case 'f':
                if ((f = fopen(optarg,"r")) == NULL) {
                    perror("Error opening file");
                    exit(1);
                }
                break;
            case 'e':
                if ((f = popen(optarg,"r")) == NULL) {
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
                pipe_cmd = optarg;
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
        data = sdsreadfile(f);
    } else {
        data = sdsread(f,n);
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

    if (pipe_cmd) {
        sds temp = sdspipe(pipe_cmd,data);
        if (temp != NULL) {
            sdsfree(data);
            data = temp;
        } else {
            printf("Pipe failed\n");
        }
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
        sdsprinthex(stdout,"SHA256: ",digest,"\n");
        sdsfree(digest);
    } else if (repr) {
        sdsprintrepr(stdout,"",data,"");
    } else {
        write(1,data,sdslen(data));
    }

    /* Clean-ip */

    (pipe == 0) ? fclose(f) : pclose(f);
    sdsfree(data);
    sdsfree(key);
    exit(0);
}
