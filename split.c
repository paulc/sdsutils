
#include <stdio.h>
#include <stdlib.h>

#include "sdsutils.h"

void *hexify(void *data) {
    return sdshex((sds)data);
}

void reducer(void *acc, void *data) {
    *(int *)acc += sdslen(data);
}

int filter_lt5(void *data) {
    int n = (int) strtol((const char *)data,NULL,10);
    return n < 5;
}

int filter_gt5(void *data) {
    int n = (int) strtol((const char *)data,NULL,10);
    return n > 5;
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
        list *map = listMap(matches,hexify,(void (*)(void *))sdsfree,(void *(*)(void *))sdsdup);
        join = listJoin(map,join_delim);
        sdsprintrepr(stdout,"Map >",join,"< \n");
        listRelease(map);
        sdsfree(join);

        // Count characters (reduce)
        int acc = 0;
        listReduce(matches,&acc,reducer);
        printf("Reduce: %d\n",acc);
        
        // Filter
        list *filtered;
        filtered = listFilter(matches,filter_gt5);
        join = listJoin(filtered,join_delim);
        sdsprintrepr(stdout,"Filtered (>5) : ",join,"\n");
        listRelease(filtered);
        sdsfree(join);

        filtered = listFilterDup(matches,filter_lt5);
        join = listJoin(filtered,join_delim);
        sdsprintrepr(stdout,"Filtered (<5) : ",join,"\n");
        listRelease(filtered);
        sdsfree(join);

        // Ranges 
        list *range;

        range = listRange(matches,0,0);
        join = listJoin(range,join_delim);
        sdsprintrepr(stdout,"Range (0,0) : ",join,"\n");
        listRelease(range);
        sdsfree(join);

        range = listRange(matches,1,3);
        join = listJoin(range,join_delim);
        sdsprintrepr(stdout,"Range (1,3) : ",join,"\n");
        listRelease(range);
        sdsfree(join);

        range = listRangeDup(matches,1,-1);
        join = listJoin(range,join_delim);
        sdsprintrepr(stdout,"Range (1,-1) : ",join,"\n");
        listRelease(range);
        sdsfree(join);

        range = listRangeDup(matches,2,-2);
        join = listJoin(range,join_delim);
        sdsprintrepr(stdout,"Range (2,-2) : ",join,"\n");
        listRelease(range);
        sdsfree(join);

        map = listMap(matches,hexify,(void (*)(void *))sdsfree,(void *(*)(void *))sdsdup);
        range = listRangeDup(map,2,-2);
        join = listJoin(range,join_delim);
        sdsprintrepr(stdout,"Mapped Range (2,-2) : ",join,"\n");
        listRelease(range);
        sdsfree(join);
        listRelease(map);

        range = listRange(NULL,0,0);
        join = listJoin(range,join_delim);
        sdsprintrepr(stdout,"NULL : ",join,"\n");
        //listRelease(range);
        //sdsfree(join);

        listRelease(matches);
	}
    sdsfree(split_delim);
    sdsfree(join_delim);
    exit(0);
}
