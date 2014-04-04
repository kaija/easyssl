
CFLAGS+= -I. -Wall
CFLAGS+= -Werror
LDFLAGS+=-lssl -lcrypto
all: client server

client: easy_ssl.o client.o
	$(CC) -o client.exe client.o easy_ssl.o $(CFLAGS) $(LDFLAGS)

server: easy_ssl.o server.o
	$(CC) -o server.exe server.o easy_ssl.o $(CFLAGS) $(LDFLAGS)


clean:
	rm -rf *.o *.a *.exe
