
OBJS_LIB=easyssl.o
STATIC_LIB=libeasyssl.a


CFLAGS+= -I. -Wall
CFLAGS+= -Werror
LDFLAGS+=-lssl -lcrypto

all: static client server

static: $(OBJS_LIB)
	$(AR) rcs $(STATIC_LIB) $(OBJS_LIB)

client: easyssl.o client.o
	$(CC) -o client.exe client.o easyssl.o $(CFLAGS) $(LDFLAGS)

server: easyssl.o server.o
	$(CC) -o server.exe server.o easyssl.o $(CFLAGS) $(LDFLAGS)


clean:
	rm -rf *.o *.a *.exe
