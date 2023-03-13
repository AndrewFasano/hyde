# CFLAGS needs -fcoroutines with gcc. But the internet claims
# gcc is terrible with coroutines. Not sure if I believe that, but
# I'm getting internal compiler errors now so let's give clang a shot!

CC=clang++-15
CFLAGS=-shared -g -I../qemu/accel/kvm/ -std=c++20 -fPIC
LDFLAGS=


all: attest.so envmgr.so hyperptrace.so sharedfolder.so pre_write.so

test: test.cpp
	g++ -fcoroutines -g -I../qemu/accel/kvm/ -std=c++20 test.cpp -o test

pwreset.so: pwreset.cpp
		$(CC) $(CFLAGS) $< $(LDFLAGS) -lcrypt -o $@

%.so : %.cpp
		$(CC) $(CFLAGS) $< $(LDFLAGS) -o $@

clean:
	rm -f *.so
