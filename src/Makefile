#CFLAGS= -std=gnu99
CFLAGS= -std=c99
#CC="$(TARGET_CC) -fhonour-cflags".
# CFLAGS="-WALL" make superman
DEPS = #types.h network.h packet.h
LIBS=$(LDFLAGS) -L. -lpcap #-lssl -luci -lcrypto -lrt -lpthread -lcurl -ljson-c  -liwinfo
OBJ = superman.o network.o packet.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $<

superman: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

clean:
	rm -rf *.o 
	rm -rf superman

