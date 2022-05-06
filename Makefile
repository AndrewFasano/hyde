CFLAGS=-shared -fcoroutines -g -I../qemu/accel/kvm/

all: norootid

norootid: norootid.cpp
	$(CC) norootid.cpp $(CFLAGS) -o norootid.so
