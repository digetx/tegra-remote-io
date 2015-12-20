CC := armv7a-hardfloat-linux-gnueabi-gcc

all: remote_io_srv

remote_io_srv: server.c api.h
	$(CC) -Wall -static -pthread -o $@ server.c

clean:
	rm remote_io_srv
