CFLAGS=-shared -fcoroutines -g -I../qemu/accel/kvm/

all: norootid.so envmgr.so shiftstderr.so alwaysroot.so

%.so : %.cpp
		$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f norootid.so envmgr.so shiftstderr.so alwaysroot.so
