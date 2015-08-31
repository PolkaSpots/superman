CFLAGS= -std=gnu99
# CFLAGS= -std=c99
#CC="$(TARGET_CC) -fhonour-cflags".
# CFLAGS= -Wall -m32 -O -g
DEPS = endian.h #types.h network.h packet.h
LIBS=$(LDFLAGS) -L. -lpcap -ljson-c -lssl -lcurl #-luci -lcrypto -lrt -lpthread -lcurl -ljson-c  -liwinfo
OBJ = superman.o radiotap.o #network.o packet.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $<

superman: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

clean:
	rm -rf *.o 
	rm -rf superman

# superman: superman.c radiotap.c
# 	gcc -o superman superman.c radiotap.c -I. -lpcap
