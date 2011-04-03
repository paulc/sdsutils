
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sds.h"
#include "sdsutils.h"

#define USAGE "Usage: readfile [-f <file>] [-n <count>] [-r|-u] [-c|-d] [-z|-Z] [-s] [-k <key>|-K <keyfile>]\n" \
              "       readfile [--long-options]\n" \
              "       readfile [-h|--help]\n" \
              "\n" \
              "       Read data from stdin & write to stdout (possibly transforming)\n"

#define HELP  "           -f,--file <file>        : Read from <file> rather than stdin\n" \
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

    while ((ch = getopt_long(argc, argv, "f:n:rucdzZkKsh", longopts, NULL)) != -1) {
        switch(ch) {
            case 'f':
                if ((f = fopen(optarg,"r")) == NULL) {
                    perror("Error opening file");
                    exit(1);
                }
                break;
            case 'n':
                if ((n = strtol(optarg,(char **) NULL,10)) == 0) {
                    perror("Invalid value");
                    exit(1);
                }
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
    
    fprintf(stderr,">>> repr=%d unrepr=%d sha256=%d compress=%d decompress=%d encrypt=%d decrypt=%d\n",
                repr,unrepr,sha256,compress,decompress,encrypt,decrypt);

    if (n == 0) {
        data = sdsreadfile(f);
    } else {
        data = sdsread(f,n);
    }

    if (unrepr) {
        sds r = sdsunrepr(data);
        sdsfree(data);
        data = r;
    }

    if (compress) {
        sds z = sdscompress(data);
        if (z != NULL) {
            sdsfree(data);
            data = sdsnewlen("lzf\0",4);
            data = sdscatlen(data,z,sdslen(z));
            sdsfree(z);
        }
    }

    if (decompress && memcmp(data,"lzf\0",4) == 0) {
        data = sdsrange(data,4,sdslen(data));
        sds z = sdsdecompress(data);
        if (z != NULL) {
            sdsfree(data);
            data = z;
        }
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

    sdsfree(data);
    sdsfree(key);
    exit(0);
}
