
#include <stdio.h>
#include <stdlib.h>

#include "sds.h"
#include "sdsutils.h"

int main(int argc, char** argv) {
	if (argc != 3) {
		printf("Usage: ./int64 <len> <value>\n");
		exit(1);
	}
    sds s = sdsempty();
    int len = strtol(argv[1],(char **)NULL,10);
    int64_t i = strtoll(argv[2],(char **)NULL,10);
    s = sdscatint(s,i,len);
    sdsprinthex(stdout,"Encoded  : ",s,"\n");
    int64_t n = sdsgetint(s,len);
    printf("Decoded  : %lld\n",n);
    printf("Original : %lld\n",i);
    sdsfree(s);
    exit(0);
}
