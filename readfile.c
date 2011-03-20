
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sds.h"
#include "sdsutils.h"

int main(int argc, char** argv) {
    FILE *f = stdin;
    int repr = 0;
    int unrepr = 0;
    int sha256 = 0;
    int compress = 0;
    int decompress = 0;
    long n = 0;
    int i = 1;
    sds data;

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
        } else if (strncmp(argv[i],"-sha256",8)==0) {
            sha256 = 1;
        } else if (strncmp(argv[i],"-h",3)==0) {
            printf("Usage: ./readfile [-r|-u] [-c|-d] [-sha256] [-n <count>] [-f <file>]\n");
            printf("\n");
            printf("       Read data from stdin & write to stdout (possibly transforming)\n");
            printf("\n");
            printf("       -r           : Quote output using sdsrepr\n");
            printf("       -u           : Unquote input using sdsunrepr\n");
            printf("       -c           : Compress output using lzf\n");
            printf("       -d           : Decompress input using lzf\n");
            printf("       -sha256      : Return SHA256 of input data\n");
            printf("       -n <count>   : Read <count> bytes from stdin|file\n");
            printf("       -f <file>    : Read from <file> rather than stdin\n");
            printf("\n");
            exit(1);
        }
        i++;
    }

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
            data = z;
        }
    }

    if (decompress) {
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
    exit(0);
}
