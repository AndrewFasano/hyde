CFLAGS=-shared -fcoroutines -g -I../qemu/accel/kvm/ -std=c++20 -fPIC

all: norootid.so envmgr.so shiftstderr.so alwaysroot.so libhook.so \
		 win_fileopen.so win_exec.so sleep_shellcode.so libhook_call.so

%.so : %.cpp
		$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f *.so
