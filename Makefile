
CFLAGS+= -I.
LDFLAGS+=-lssl -lcrypto
all: sample
sample: easy_ssl.o client.o
	$(CC) -o easy_ssl.exe client.o easy_ssl.o $(CFLAGS) $(LDFLAGS)

clean:
	rm -rf *.o *.a *.exe
