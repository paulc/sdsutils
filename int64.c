
#include <stdio.h>
#include <stdlib.h>

#include "sds.h"
#include "sdsutils.h"

int main(int argc, char** argv) {
	if (argc != 2) {
		printf("Usage: ./int64 <value>\n");
		exit(1);
	}
    sds s = sdsempty();
    int64_t i = strtoll(argv[1],(char **)NULL,10);
    s = sdscatint64(s,i);
    sdsprintrepr(stdout,"Encoded  : ",s,"\n");
    int64_t n = sdsgetint64(s);
    printf("Decoded  : %lld\n",n);
    printf("Original : %lld\n",i);
    sdsfree(s);
    exit(0);
}
