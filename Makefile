CFLAGS=-shared -fcoroutines -g -I../qemu/accel/kvm/ -std=c++20 -fPIC

all: norootid.so envmgr.so shiftstderr.so alwaysroot.so libhook.so

%.so : %.cpp
		$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f norootid.so envmgr.so shiftstderr.so alwaysroot.so
