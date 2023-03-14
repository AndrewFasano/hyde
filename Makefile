# CFLAGS needs -fcoroutines if building with gcc. But the internet claims
# gcc is terrible with coroutines. Not sure if I believe that, but
# I'm getting internal compiler errors now so let's give clang a shot!

CXX=clang++-15
CFLAGS=-shared -g -I../qemu/accel/kvm/ -std=c++20 -fPIC
LDFLAGS=


all: attest.so envmgr.so hyperptrace.so sharedfolder.so pre_write.so

test: test.cpp
	$(CXX) --std=c++20 -g $< -o $@

pwreset.so: pwreset.cpp
	$(CXX) $(CFLAGS) $< $(LDFLAGS) -lcrypt -o $@

%.so : %.cpp
	$(CXX) $(CFLAGS) $< $(LDFLAGS) -o $@

clean:
	rm -f *.so
