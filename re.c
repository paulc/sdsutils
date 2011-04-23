
#include <stdio.h>
#include <stdlib.h>

#include "sdsutils.h"

int main(int argc, char** argv) {
	if (argc != 2) {
		printf("Usage: ./re <regex>\n");
		exit(1);
	}
	while (!feof(stdin)) {
		sds line = sdsreadline(stdin,">> ");
        list *matches = sdsmatch(line,argv[1]);

        if (matches == NULL) {
            printf("Problem compiling regex: %s\n",argv[1]);
            exit(1);
        }

        listIter *iter = listGetIterator(matches,AL_START_HEAD);
        listNode *node;

        while ((node = listNext(iter)) != NULL) {
            sdsprintrepr(stdout,"Match: ",(sds)listNodeValue(node),"\n");
        } 

        listReleaseIterator(iter);
        listRelease(matches);
        sdsfree(line);
	}
    exit(0);
}
