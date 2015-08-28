CC = -std=gnu99
#CFLAGS=-Wall -m32 -O -g
#LDFLAGS = -m32 -O -g

#CFLAGS= -std=c99
#CC="$(TARGET_CC) -fhonour-cflags".
# CFLAGS= -Wall -m32 -O -g
# DEPS = #types.h network.h packet.h
# LIBS=$(LDFLAGS) -L. -lpcap #-lssl -luci -lcrypto -lrt -lpthread -lcurl -ljson-c  -liwinfo
# OBJ = superman.o Radiotap.o #network.o packet.o

# %.o: %.c $(DEPS)
# 	$(CC) -c -o $@ $<

superman: superman.c radiotap.c
	gcc -o superman superman.c radiotap.c -I. -lpcap

# superman: $(OBJ)
# 	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

clean:
	rm -rf *.o 
	rm -rf superman

