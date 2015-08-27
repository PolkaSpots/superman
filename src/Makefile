CFLAGS= -std=gnu99
DEPS = curl_calls.h iwinfo.h
LIBS=$(LDFLAGS) -L. -lssl -luci -lcrypto -lrt -lpthread -lcurl -ljson-c  -liwinfo
OBJ =superman.o 

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $<

superman: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

clean:
	rm -rf *.o 
	rm -rf superman

