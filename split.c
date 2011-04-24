
#include <stdio.h>
#include <stdlib.h>

#include "sdsutils.h"

void _sdsfree(void *ptr) {
    printf("--> Free: %p %s\n",ptr, (char *)ptr);
    sdsfree((sds) ptr);
}

void *hexify(listNode *node,void *state) {
    sds in = (sds)listNodeValue(node);
    sds result = sdshex(in);
    *(int *)state += 1;
    printf("Map: %s -> %s\n", (char *)in, (char *)result);
    return result;
}

int main(int argc, char** argv) {
	if (argc != 3) {
		printf("Usage: ./re <split delim> <join delim>\n");
		exit(1);
	}
    sds arg = sdsnew(argv[1]);
    sds split_delim = sdsunrepr(arg);
    sdsfree(arg);

    arg = sdsnew(argv[2]);
    sds join_delim = sdsunrepr(arg);
    sdsfree(arg);


	while (!feof(stdin)) {
		sds line = sdsreadline(stdin,"Line: ");
        list *matches = sdssplit(line,split_delim);
        sdsfree(line);

        listIter *iter = listGetIterator(matches,AL_START_HEAD);
        listNode *node;

        while ((node = listNext(iter)) != NULL) {
            sdsprintrepr(stdout,">>",(sds)listNodeValue(node),"<<\n");
        } 

        listReleaseIterator(iter);

        int count=0;
        list *map = listMapWithState(matches,hexify,_sdsfree,(void *)&count);
        sds join = listJoin(map,join_delim);
        sdsprintrepr(stdout,"Map >",join,"< \n");
        printf("Count=%d\n",count);
        listRelease(map);
        sdsfree(join);

        listRelease(matches);
	}
    sdsfree(split_delim);
    sdsfree(join_delim);
    exit(0);
}
