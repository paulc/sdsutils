
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sds.h"
#include "sdsutils.h"

int main(int argc, char** argv) {
    FILE *f;
	if (argc != 3) {
		printf("Usage: ./readfile <file> <count>\n");
		exit(1);
	}
    if (strcmp(argv[1],"-") == 0) {
        f = stdin;
    } else {
        if ((f = fopen(argv[1],"r")) == NULL) {
            perror("Error opening file");
            exit(1);
        }
    }
    long n = strtol(argv[2],(char **)NULL,10);
    sds data = sdsread(f,n);
    //sdsrepr(stdout,data);
    write(1,data,sdslen(data));
    sdsfree(data);
    exit(0);
}
