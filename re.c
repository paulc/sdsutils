
#include <stdio.h>
#include <stdlib.h>

#include "sds.h"
#include "sdsutils.h"

int main(int argc, char** argv) {
	if (argc != 2) {
		printf("Usage: ./re <regex>\n");
		exit(1);
	}
	while (!feof(stdin)) {
		sds line = sdsreadline(stdin,">> ");
        int count = 0;
        sds *matches = sdsmatch(line,argv[1],&count);
        if (matches == NULL) {
            printf("Problem compiling regex: %s\n",argv[1]);
            exit(1);
        }
        for (int i=0; i<count; i++) {
            printf("Match %d: ",i);
            sdsprintrepr(stdout,"",matches[i],"\n");
        }
        sdsfreematchres(matches,count);
        sdsfree(line);
	}
    exit(0);
}
