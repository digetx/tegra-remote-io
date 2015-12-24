CC      := armv7a-hardfloat-linux-gnueabi-gcc
CC_AVP  := armv6j-softfloat-linux-gnueabi-gcc
OBJCOPY := armv6j-softfloat-linux-gnueabi-objcopy

all: remote_io_srv

avp.o: avp.c ld-script
	$(CC_AVP) -Os -Wall -fPIE -march=armv4t -nostdlib -mfloat-abi=soft -T ld-script -o $@ $<

avp.bin: avp.o
	$(OBJCOPY) -O binary $< -S $@

avp.h: avp.bin avp.o offset.sh
	xxdi.pl $< > $@
	./offset.sh avp.o avp_start AVP_ENTRY_ADDR >> $@
	./offset.sh avp.o avp_arg1  AVP_ARG1 >> $@
	./offset.sh avp.o avp_arg2  AVP_ARG2 >> $@
	./offset.sh avp.o avp_res   AVP_RES >> $@
	./offset.sh avp.o avp_act   AVP_ACT >> $@

remote_io_srv: server.c api.h avp.h
	$(CC) -Wall -pthread -g -o $@ server.c

clean:
	rm avp.h avp.bin avp.o remote_io_srv
