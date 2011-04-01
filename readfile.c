
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sds.h"
#include "sdsutils.h"

#define USAGE "\nUsage: readfile [-r|-u] [-c|-d] [-sha256] [-n <count>] [-z|-Z] [-k <key>|-kf <keyfile>] [-f <file>]\n" \
              "       readfile -h\n\n" \
              "       Read data from stdin & write to stdout (possibly transforming)\n"

int main(int argc, char** argv) {
    FILE *f = stdin;
    int repr = 0;
    int unrepr = 0;
    int sha256 = 0;
    int compress = 0;
    int decompress = 0;
    int encrypt = 0;
    int decrypt = 0;
    long n = 0;
    int i = 1;
    sds data = NULL;
    sds key = NULL;

    while (i < argc && argv[i][0] == '-') {
        if (strncmp(argv[i],"-r",3)==0) {
            repr = 1;
        } else if (strncmp(argv[i],"-u",3)==0) {
            unrepr = 1;
        } else if (strncmp(argv[i],"-f",3)==0) {
            if ((f = fopen(argv[++i],"r")) == NULL) {
                perror("Error opening file");
                exit(1);
            }
        } else if (strncmp(argv[i],"-n",3)==0) {
            n = strtol(argv[++i],(char **)NULL,10);
        } else if (strncmp(argv[i],"-c",3)==0) {
            compress = 1;
        } else if (strncmp(argv[i],"-d",3)==0) {
            decompress = 1;
        } else if (strncmp(argv[i],"-z",3)==0) {
            encrypt = 1;
        } else if (strncmp(argv[i],"-Z",3)==0) {
            decrypt = 1;
        } else if (strncmp(argv[i],"-k",3)==0) {
            if (++i >= argc) {
                fprintf(stderr,USAGE);
                exit(1);
            }
            key = sdsnew(argv[i]);
        } else if (strncmp(argv[i],"-kf",4)==0) {
            if (++i >= argc) {
                fprintf(stderr,USAGE);
                exit(1);
            }
            FILE *kf;
            if ((kf = fopen(argv[i],"r")) == NULL) {
                perror("Unable to read keyfile");
                exit(1);
            }
            if ((key = sdsreadfile(kf)) == NULL) {
                perror("Unable to read keydata");
                sdsfree(key);
                exit(1);
            }
            fclose(kf);
        } else if (strncmp(argv[i],"-sha256",8)==0) {
            sha256 = 1;
        } else if (strncmp(argv[i],"-h",3)==0) {
            printf(USAGE);
            printf("\n");
            printf("       -r             : Quote output using sdsrepr\n");
            printf("       -u             : Unquote input using sdsunrepr\n");
            printf("       -c             : Compress output using lzf\n");
            printf("       -d             : Decompress input using lzf\n");
            printf("       -z             : Encrypt data\n");
            printf("       -Z             : Decrypt data\n");
            printf("       -k <key>       : Key (unsafe)\n");
            printf("       -kf <keyfile>  : Read key from file\n");
            printf("       -Z             : Decrypt data (requires -k/-kf)\n");
            printf("       -sha256        : Return SHA256 of input data\n");
            printf("       -n <count>     : Read <count> bytes from stdin|file\n");
            printf("       -f <file>      : Read from <file> rather than stdin\n");
            printf("\n");
            exit(1);
        }
        i++;
    }

    // fprintf(stderr,">>> repr=%d unrepr=%d sha256=%d compress=%d decompress=%d encrypt=%d decrypt=%d\n",
    //            repr,unrepr,sha256,compress,decompress,encrypt,decrypt);

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
