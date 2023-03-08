CFLAGS=-shared -fcoroutines -g -I../qemu/accel/kvm/ -std=c++20 -fPIC 
LDFLAGS=


all: attest.so envmgr.so hyperptrace.so sharedfolder.so pre_write.so

test: test.cpp
	g++ -fcoroutines -g -I../qemu/accel/kvm/ -std=c++20 test.cpp -o test

%.so : %.cpp
		$(CC) $(CFLAGS) $< $(LDFLAGS) -o $@

clean:
	rm -f *.so
