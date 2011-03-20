
CC ?= gcc
AR ?= ar
CFLAGS = -Wall -Werror -O2 -std=gnu99
LDFLAGS = 
DEBUG ?= -g -rdynamic -ggdb

OBJ = blowfish.o sds.o zmalloc.o sdsutils.o slre.o sha256.o lzf_c.o lzf_d.o
LIB = libsdsutil.a
PROGS = int64 re readfile encrypt

all : $(PROGS)

# Deps (from 'make dep')
blowfish.o: blowfish.c blowfish.h
encrypt.o: encrypt.c sds.h sdsutils.h slre.h
int64.o: int64.c sds.h sdsutils.h slre.h
lzf_c.o: lzf_c.c lzfP.h
lzf_d.o: lzf_d.c lzfP.h
re.o: re.c sds.h sdsutils.h slre.h
readfile.o: readfile.c sds.h sdsutils.h slre.h
sds.o: sds.c sds.h zmalloc.h
sdsutils.o: sdsutils.c sdsutils.h sds.h slre.h blowfish.h sha256.h \
  zmalloc.h
sha256.o: sha256.c sha256.h
slre.o: slre.c slre.h
zmalloc.o: zmalloc.c config.h

# Targets
int64 : int64.o $(OBJ)
	$(CC) -o int64 $(LDFLAGS) $(DEBUG) int64.o $(OBJ)

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
	rm -rf $(PROGS) $(LIB) *.o *~ $(PROGS)

