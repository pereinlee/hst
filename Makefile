CC=$(TOOLPREFIX)gcc
CFLAGS= -g
IMPLEMENTPATH=$(PWD)
INCLUDE= -I$(IMPLEMENTPATH) -I$(IMPLEMENTPATH)/../../public/ -I$(IMPLEMENTPATH)/../common/
OBJ=$(IMPLEMENTPATH)/hst_common.c $(IMPLEMENTPATH)/main.c
LIBPATH= -L$(INSTALL_ROOT)/lib -ljson -lm -liw -lcom
all: hstresource
	echo $(IMPLEMENTPATH)
hstresource:
	$(CC) -o $@ $^ $(CFLAGS) $(OBJ) $(INCLUDE) $(LIBPATH)
clean:
	rm -rf *.o hstresource 
