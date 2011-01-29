
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sds.h"
#include "sdsutils.h"

#define USAGE "Usage: encrypt [-e|-d] [-i] -k <key> | -kf <keyfile>"

int main(int argc, char** argv) {

    int i = 1;
    int encrypt = 1;
    int interactive = 0;
    sds key = NULL;

    while (i < argc && argv[i][0] == '-') {
        if (strncmp(argv[i],"-e",3)==0) {
            encrypt = 1;
        } else if (strncmp(argv[i],"-d",3)==0) {
            encrypt = 0;
        } else if (strncmp(argv[i],"-i",3)==0) {
            interactive = 1;
        } else if (strncmp(argv[i],"-k",3)==0) {
            if (++i >= argc) {
                fprintf(stderr,"%s\n",USAGE);
                exit(1);
            }
            key = sdsnew(argv[i]);
        } else if (strncmp(argv[i],"-kf",4)==0) {
            if (++i >= argc) {
                fprintf(stderr,"%s\n",USAGE);
                exit(1);
            }

            FILE *kf;
            if ((kf = fopen(argv[i],"r")) == NULL) {
                perror("Unable to read keyfile");
                exit(1);
            }

            if ((key = sdsreadfile(kf)) == NULL) {
                perror("Unable to read keydata");
                exit(1);
            }

            fclose(kf);

        } else if (strncmp(argv[i],"-h",3)==0) {
            printf("%s\n\n",USAGE);
            printf("  -e            Encrypt (default)\n");
            printf("  -d            Decrypt\n");
            printf("  -i            Interactive\n");
            printf("  -k <key>      Key\n");
            printf("  -kf <keyfile> Key\n");
            exit(1);
        }
        i++;
    }

    if (key == NULL) {
        fprintf(stderr,"%s\n",USAGE);
        exit(1);
    }

    if (sdslen(key) < 8) {
        fprintf(stderr,"Key too short (min 8 chars)\n");
        exit(1);
    }

    FILE *random;
    if ((random = fopen("/dev/urandom","r")) == NULL) {
        perror("Error opening /dev/urandom");
        exit(1);
    }

    if (interactive == 1) {
        while (!feof(stdin)) {
            sds line = sdsreadline(stdin,">> ");
            sds iv = sdsread(random,8);
            if (iv == NULL || sdslen(iv) != 8) {
                fprintf(stderr,"Error reading IV\n");
                exit(1);
            }
            sds z = sdsencrypt(line,key,iv);
            sdsrepr(stdout,"Data:      ",line,"\n");
            sdsrepr(stdout,"Key:       ",key,"\n");
            sdsrepr(stdout,"IV:        ",iv,"\n");
            sdsrepr(stdout,"Encrypted: ",z,"\n");
            sds s = sdsdecrypt(z,key);
            sdsrepr(stdout,"Decrypted: ",s,(sdscmp(s,line) == 0) ? " - OK\n" : " - Error\n");
            sdsfree(iv);
            sdsfree(line);
            sdsfree(z);
            sdsfree(s);
        }
    } else {
        sds data = sdsreadfile(stdin);
        sds z = NULL;
        if (data == NULL) {
            fprintf(stderr,"Error reading data\n");
            exit(1);
        }
        if (encrypt) {
            sds iv = sdsread(random,8);
            if (iv == NULL || sdslen(iv) != 8) {
                fprintf(stderr,"Error reading IV\n");
                exit(1);
            }
            z = sdsencrypt(data,key,iv);
            sdsfree(iv);
        } else {
            z = sdsdecrypt(data,key);
        }
        if (fwrite(z,1,sdslen(z),stdout) != sdslen(z)) {
            fprintf(stderr,"Error writing data\n");
            exit(1);
        }
        sdsfree(data);
        sdsfree(z);
    }

    sdsfree(key);
    exit(0);
}
