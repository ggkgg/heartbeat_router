HB_CLIENT = hb_client

####### x86 mips ######
PLATFORM := x86
DEBUG_CMP := y
#DEBUG_LIB :=
ENCRY := DES



ifeq ($(PLATFORM),x86)
CC = gcc
STRIP = strip
LDFLAGS =

CFLAGS = -I.
ifeq ($(DEBUG_CMP),y)
CFLAGS += -g -rdynamic
endif

CCOMPILE = $(CC) $(LDFLAGS) $(CFLAGS) -c  
LIBS = -L. -L/usr/lib64
LIBEX = 
LIBA =
endif

ifeq ($(PLATFORM),mips)
CC = /opt/buildroot-gcc463/usr/bin/mipsel-buildroot-linux-uclibc-gcc
STRIP = /opt/buildroot-gcc463/usr/bin/mipsel-buildroot-linux-uclibc-strip
LDFLAGS =

CFLAGS = -I. -I/home/pengrf/workspace/libxml2-2.7.8/target/include/libxml2
ifeq ($(DEBUG_CMP),y)
CFLAGS += -g -rdynamic
endif

CCOMPILE = $(CC) $(LDFLAGS) $(CFLAGS) -c  
LIBS =-L. -L/opt/buildroot-gcc463/usr/mipsel-buildroot-linux-uclibc/sysroot/lib/ -L/home/pengrf/workspace/libxml2-2.7.8/target/lib
LIBEX = -lauth_core -lpthread -lxml2
LIBA =
endif



HB_CLIENT_SRC := hb_client.c hb_core.c debug.c profile.c

ifeq ($(ENCRY),DES)
HB_CLIENT_SRC += des.c deskey.c
CFLAGS += -DCRYTO_DES
endif
#ifdef DEBUG_LIB
#HB_CLIENT_SRC += debug.c
#AUTH_CORE_SRC += debug.c
#CFLAGS += -DDEBUG_LIB
#endif

all:$(HB_CLIENT)
	#$(STRIP) $(HB_CLIENT)

$(HB_CLIENT):  
	$(CC) -o $@ $(HB_CLIENT_SRC) $(CFLAGS) $(LDFLAGS) $(LIBS) $(LIBEX)

$(AUTH_CLI):  
	$(CC) -o $@ auth_cli.c $(CFLAGS) $(LIBS) $(LIBEX)	
	
$(AUTH_CORE):
	$(CC) -o libauth_core.so $(AUTH_CORE_SRC) -fPIC -shared $(CFLAGS) $(LDFLAGS)
	

IPC_CLIENT_LIBEX = -lauth_core -lpthread
$(IPC_CLIENT):
	$(CC) -o $@ unix_ipc_client.c $(LIBS) $(IPC_CLIENT_LIBEX)	

$(AUTH_MARKET):
	$(CC) -o $@ auth_market.c $(CFLAGS) $(LIBS) $(LIBEX)

	
.PHONY: clean backup
clean: 
	rm -f $(HB_CLIENT) *.o

HFILE := cJSON.h debug.h dms_dev.h dms_zigbee.h InnerClient.h list.h utils.h wireless.h
backup:
	rm backup -rf
	mkdir backup
	cp $(CSRCS) $(CXXSRCS) $(HFILE) Makefile backup
