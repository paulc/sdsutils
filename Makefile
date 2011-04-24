
CC ?= gcc
AR ?= ar
CFLAGS = -Wall -Werror -O2 -std=gnu99
LDFLAGS = 
DEBUG ?= -g -rdynamic -ggdb

OBJ = blowfish.o sds.o zmalloc.o sdsutils.o slre.o sha256.o lzf_c.o lzf_d.o adlist.o
LIB = libutil.a
PROGS = int64 re readfile encrypt split

all : $(PROGS) $(LIB)

# Deps (from 'make dep')
adlist.o: adlist.c adlist.h zmalloc.h
blowfish.o: blowfish.c blowfish.h
encrypt.o: encrypt.c sds.h sdsutils.h adlist.h blowfish.h lzf.h sha256.h \
  slre.h zmalloc.h
int64.o: int64.c sds.h sdsutils.h adlist.h blowfish.h lzf.h sha256.h \
  slre.h zmalloc.h
lzf_c.o: lzf_c.c lzfP.h
lzf_d.o: lzf_d.c lzfP.h
re.o: re.c sdsutils.h adlist.h blowfish.h lzf.h sds.h sha256.h slre.h \
  zmalloc.h
readfile.o: readfile.c adlist.h sds.h sdsutils.h blowfish.h lzf.h \
  sha256.h slre.h zmalloc.h
sds.o: sds.c sds.h zmalloc.h
sdsutils.o: sdsutils.c sdsutils.h adlist.h blowfish.h lzf.h sds.h \
  sha256.h slre.h zmalloc.h
sha256.o: sha256.c sha256.h
slre.o: slre.c slre.h
split.o: split.c sdsutils.h adlist.h blowfish.h lzf.h sds.h sha256.h \
  slre.h zmalloc.h
zmalloc.o: zmalloc.c config.h

# Targets
readfile : readfile.o $(OBJ)
	$(CC) -o readfile $(LDFLAGS) $(DEBUG) readfile.o $(OBJ)

int64 : int64.o $(OBJ)
	$(CC) -o int64 $(LDFLAGS) $(DEBUG) int64.o $(OBJ)

re : re.o $(OBJ)
	$(CC) -o re $(LDFLAGS) $(DEBUG) re.o $(OBJ)

encrypt: encrypt.o $(OBJ)
	$(CC) -o encrypt $(LDFLAGS) $(DEBUG) encrypt.o $(OBJ)

split: split.o $(OBJ)
	$(CC) -o split $(LDFLAGS) $(DEBUG) split.o $(OBJ)

# Lib
$(LIB) : $(OBJ)
	$(AR) rcs $(LIB) $(OBJ)

# Generic build targets
.c.o:
	$(CC) -c $(CFLAGS) $(DEBUG) $<

dep:
	$(CC) -MM *.c

clean:
	rm -rf $(PROGS) $(LIB) *.o *~ 

