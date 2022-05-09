CFLAGS=-shared -fcoroutines -g -I../qemu/accel/kvm/

all: norootid envmgr

norootid: norootid.cpp
	$(CC) norootid.cpp $(CFLAGS) -o norootid.so

envmgr: envmgr.cpp
	$(CC) envmgr.cpp $(CFLAGS) -o envmgr.so
