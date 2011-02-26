
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sds.h"
#include "sdsutils.h"

int main(int argc, char** argv) {
    FILE *f = stdin;
    int repr = 0;
    int sha256 = 0;
    long n = 0;
    int i = 1;
    sds data;

    while (i < argc && argv[i][0] == '-') {
        if (strncmp(argv[i],"-r",3)==0) {
            repr = 1;
        } else if (strncmp(argv[i],"-f",3)==0) {
            if ((f = fopen(argv[++i],"r")) == NULL) {
                perror("Error opening file");
                exit(1);
            }
        } else if (strncmp(argv[i],"-n",3)==0) {
            n = strtol(argv[++i],(char **)NULL,10);
        } else if (strncmp(argv[i],"-sha256",8)==0) {
            sha256 = 1;
        } else if (strncmp(argv[i],"-h",3)==0) {
            printf("Usage: ./readfile [-r] [-sha256] [-n <count>] [-f <file>]\n");
            exit(1);
        }
        i++;
    }

    if (n == 0) {
        data = sdsreadfile(f);
    } else {
        data = sdsread(f,n);
    }

    if (sha256) {
        sds digest = sdssha256(data);
        sdsprinthex(stdout,"",digest,"\n");
        sdsfree(digest);
    } else if (repr) {
        sdsprintrepr(stdout,"",data,"");
    } else {
        write(1,data,sdslen(data));
    }

    sdsfree(data);
    exit(0);
}
