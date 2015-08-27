CC = cc
# CFLAGS = -std=c99 -pedantic -Wall
CFLAGS="-Wall" make ex1
OBJECTS = ex1.o

all: appname

filename.o: ex1.c
	    $(CC) $(CFLAGS) -c ex1.c

appname: $(OBJECTS)
	    $(CC) $(OBJECTS) -o ex1

clean:
	    rm -f *.o ex1
