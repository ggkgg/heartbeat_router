HB_CLIENT = hb_client
SRC = src
OBJ = obj
LIB = lib

$(shell mkdir obj)

####### x86 mips463 mips342 ######
#PLATFORM := x86
PLATFORM := mips342

DEBUG_CMP := y
#DEBUG_LIB :=
ENCRY := DES
CVNWARE := 

ifneq ($(PLATFORM),x86)
MTK := y
endif

##########################  platform for x86 #######################
ifeq ($(PLATFORM),x86)
CC = gcc
STRIP = strip
LIBS += -L./$(LIB) -L/usr/lib64
endif
##########################################################################

##########################  platform for mips463 #######################
ifeq ($(PLATFORM),mips463)
CC = /opt/buildroot-gcc463/usr/bin/mipsel-buildroot-linux-uclibc-gcc
STRIP = /opt/buildroot-gcc463/usr/bin/mipsel-buildroot-linux-uclibc-strip
LIBS += -L./$(LIB) -L/opt/buildroot-gcc463/usr/mipsel-buildroot-linux-uclibc/sysroot/lib/
endif
##########################################################################

##########################  platform for mips342 #######################
ifeq ($(PLATFORM),mips342)
CC = /opt/buildroot-gcc342/bin/mipsel-linux-gcc
STRIP = /opt/buildroot-gcc342/bin/mipsel-linux-strip
LIBS += -L./$(LIB) -L/opt/buildroot-gcc342/lib/
endif
#########################################################################



##########################  common for all #######################
HB_CLIENT_CSRCS := $(SRC)/hb_client.c $(SRC)/hb_core.c \
$(SRC)/debug.c $(SRC)/profile.c $(SRC)/XORcode.c \
$(SRC)/net.c $(SRC)/business.c \
$(SRC)/udpserver.c $(SRC)/ipcore.c $(SRC)/ipcmye.c $(SRC)/cJSON.c


ifeq ($(ENCRY),DES)
HB_CLIENT_CSRCS += $(SRC)/des.c $(SRC)/deskey.c
CFLAGS += -DCRYTO_DES
endif

LDFLAGS +=
CFLAGS += -I./$(SRC)
ifeq ($(DEBUG_CMP),y)
CFLAGS += -g -rdynamic 
endif

CCOMPILE = $(CC) $(LDFLAGS) $(CFLAGS) -c  
LIBEX += -lpthread -lm
LIBA =

BINDIR := ./
##########################################################################

############################# register for cvnware ###############
ifeq ($(CVNWARE),y)
CFLAGS += -I$(TOPDIR)/include -I$(TOPDIR)/uim/webs-2-5
CFLAGS += -DCVNWARE
TOPDIR := ../../..
#include $(TOPDIR)/.config
#include $(TOPDIR)/rules/libm.mk
ROMFSDIR :=../../../../sdk/RT288x_SDK/source/romfs
BINDIR := $(TOPDIR)/bin
endif
##########################################################################

############################# register for MTK ###############
ifeq ($(MTK),y)
CFLAGS += -DMTK
LIBEX += -lnvram-0.9.28
endif
##########################################################################

############################# register for x86 ###############
ifeq ($(PLATFORM),x86)
CFLAGS += -Dx86
endif
##########################################################################

#ifdef DEBUG_LIB
#HB_CLIENT_SRC += debug.c
#AUTH_CORE_SRC += debug.c
#CFLAGS += -DDEBUG_LIB
#endif

HB_CLIENT_COBJS := $(patsubst $(SRC)/%.c,$(OBJ)/%.o,$(HB_CLIENT_CSRCS))  

all:$(HB_CLIENT) test
	$(STRIP) $(HB_CLIENT)
	
$(HB_CLIENT): $(HB_CLIENT_COBJS) 
	$(CC) -o $@ $(HB_CLIENT_COBJS) $(CFLAGS) $(LDFLAGS) $(LIBS) $(LIBEX)
	
test: ipc_udpcli1
	$(STRIP) ipc_udpcli1

ipc_udpcli1: 
	$(CC) -o $@ test/ipc_udpcli1.c $(SRC)/cJSON.c -I./test -I$(SRC) -lm
	
$(DMS_DEV): $(COBJS) $(CXXOBJS)  
	$(LINKCC) $(COBJS) $(CXXOBJS) $(LIBA) -o $@ $(LIBS) $(LIBEX)
	
$(AUTH_CLI):  
	$(CC) -o $@ auth_cli.c $(CFLAGS) $(LIBS) $(LIBEX)	
	
$(AUTH_CORE):
	$(CC) -o libauth_core.so $(AUTH_CORE_SRC) -fPIC -shared $(CFLAGS) $(LDFLAGS)

./obj/%.o: src/%.c
	$(CCOMPILE) -o $@ $<
	

IPC_CLIENT_LIBEX = -lauth_core -lpthread
$(IPC_CLIENT):
	$(CC) -o $@ unix_ipc_client.c $(LIBS) $(IPC_CLIENT_LIBEX)	

$(AUTH_MARKET):
	$(CC) -o $@ auth_market.c $(CFLAGS) $(LIBS) $(LIBEX)

	
.PHONY: clean backup $(HB_CLIENT) $(TEST)
clean: 
	rm -rf obj
	rm -f $(HB_CLIENT)
	rm -f ipc_udpcli1

HFILE := cJSON.h debug.h dms_dev.h dms_zigbee.h InnerClient.h list.h utils.h wireless.h
backup:
	rm backup -rf
	mkdir backup
	cp $(CSRCS) $(CXXSRCS) $(HFILE) Makefile backup
