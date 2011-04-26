
#include <stdio.h>
#include <stdlib.h>

#include "sdsutils.h"

void _sdsfree(void *ptr) {
    //printf("--> Free: %p %s\n",ptr, (char *)ptr);
    sdsfree((sds) ptr);
}

void *hexify(void *data) {
    return sdshex((sds)data);
}

void reducer(void *acc, void *data) {
    *(int *)acc += sdslen(data);
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

        // Iterate through list
        listIter *iter = listGetIterator(matches,AL_START_HEAD);
        listNode *node;
        while ((node = listNext(iter)) != NULL) {
            sdsprintrepr(stdout,"Item >>",(sds)listNodeValue(node),"<<\n");
        } 
        listReleaseIterator(iter);

        // Join 
        sds join = listJoin(matches,join_delim);
        sdsprintrepr(stdout,"Orig >",join,"< \n");
        sdsfree(join);

        // Map
        list *map = listMap(matches,hexify,_sdsfree);
        join = listJoin(map,join_delim);
        sdsprintrepr(stdout,"Map >",join,"< \n");
        listRelease(map);
        sdsfree(join);

        // Count characters (reduce)
        int acc = 0;
        listReduce(matches,&acc,reducer);
        printf("Reduce: %d\n",acc);
        
        // Ranges (dont worry about clean up from anon list/sds
        sdsprintrepr(stdout,"Range (0,0) : ",listJoin(listRange(matches,0,0),sdsnew(",")),"\n");
        sdsprintrepr(stdout,"Range (1,3) : ",listJoin(listRange(matches,1,3),sdsnew(",")),"\n");
        sdsprintrepr(stdout,"Range (1,-1) : ",listJoin(listRange(matches,1,-1),sdsnew(",")),"\n");
        sdsprintrepr(stdout,"Range (2,-2) : ",listJoin(listRange(matches,2,-2),sdsnew(",")),"\n");

        listRelease(matches);
	}
    sdsfree(split_delim);
    sdsfree(join_delim);
    exit(0);
}
