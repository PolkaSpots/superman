CC = cc
# CFLAGS = -std=c99 -pedantic -Wall
CFLAGS="-Wall" make superman
OBJECTS = superman.o

all: superman

filename.o: superman.c
	    $(CC) $(CFLAGS) -c superman.c

appname: $(OBJECTS)
	    $(CC) $(OBJECTS) -o superman

clean:
	    rm -f *.o superman
