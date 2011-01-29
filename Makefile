
CC = gcc
AR = ar
CFLAGS = -Wall -O2 -std=c99 -D_POSIX_SOURCE
LDFLAGS = 
DEBUG ?= -g -rdynamic -ggdb

OBJ = blowfish.o linenoise.o sds.o zmalloc.o sdsutils.o slre.o 
LIB = libsdsutil.a
PROGS = re readfile encrypt

all : $(PROGS)

# Deps (from 'make dep')
blowfish.o: blowfish.c blowfish.h
encrypt.o: encrypt.c sds.h sdsutils.h slre.h
linenoise.o: linenoise.c fmacros.h
re.o: re.c sds.h sdsutils.h slre.h
readfile.o: readfile.c sds.h sdsutils.h slre.h
sds.o: sds.c sds.h zmalloc.h
sdsutils.o: sdsutils.c sdsutils.h sds.h slre.h blowfish.h zmalloc.h
slre.o: slre.c slre.h
zmalloc.o: zmalloc.c config.h

# Targets
re : re.o $(OBJ)
	$(CC) -o re $(LDFLAGS) $(DEBUG) re.o $(OBJ)

readfile : readfile.o $(OBJ)
	$(CC) -o readfile $(LDFLAGS) $(DEBUG) readfile.o $(OBJ)

encrypt: encrypt.o $(OBJ)
	$(CC) -o encrypt $(LDFLAGS) $(DEBUG) encrypt.o $(OBJ)

# Lib
$(LIB) : $(OBJ)
	$(AR) rcs $(LIB) $(OBJ)

# Generic build targets
.c.o:
	$(CC) -c $(CFLAGS) $(DEBUG) $<

dep:
	$(CC) -MM *.c

clean:
	rm -rf $(PROGS) $(LIB) *.o *~ readfile re encrypt

