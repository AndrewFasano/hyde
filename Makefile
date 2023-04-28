# CFLAGS needs -fcoroutines if building with gcc. But the internet claims
# gcc is terrible with coroutines. Not sure if I believe that, but
# I'm getting internal compiler errors now so let's give clang a shot!
CXX=clang++-15
CFLAGS=-g -I../qemu/hyde/include/ -I./sdk/ -std=c++20 -Wno-deprecated-declarations -fPIC
SO_CFLAGS=-fPIC -shared $(CFLAGS)
LDFLAGS=-fuse-ld=lld

SRCS = $(wildcard progs/*.cpp)
PROGS = $(patsubst %.cpp,%.so,$(SRCS))

HYDE = $(wildcard sdk/*.cpp)
HYDE_O = $(patsubst %.cpp,%.o,$(HYDE))
HYDE_H = $(wildcard sdk/*.h)

all: $(PROGS)

progs/gdbserver.o: progs/gdbserver.cpp
	$(CXX) $(CFLAGS) -c $< -o $@

progs/gptgdbserver: progs/gptgdbserver.cpp progs/gdbserver.o progs/gdbserver.h
	$(CXX) $(CFLAGS) $< progs/gdbserver.o -o $@

test: test.cpp
	$(CXX) $(CFLAGS) $< -o $@

templtest: templtest.cpp
	$(CXX) $(CFLAGS) $< -o $@

sdk/%.o: sdk/%.cpp $(HYDE_H)
	$(CXX) $(CFLAGS) -c $< -o $@

# Pwreset needs link with crypt
progs/pwreset.so: progs/pwreset.cpp $(HYDE_O) $(HYDE_H)
	$(CXX) $(SO_CFLAGS) $< $(LDFLAGS) $(HYDE_O) -lcrypt -o $@

# Hyperptrace needs link with pthread
progs/hyperptrace.so: progs/hyperptrace.cpp $(HYDE_O) $(HYDE_H)
	$(CXX) $(SO_CFLAGS) $< $(HYDE_O) $(LDFLAGS) -lpthread -o $@

# Normal programs just link against hyde
progs/%.so : progs/%.cpp $(HYDE_O) $(HYDE_H)
	$(CXX) $(SO_CFLAGS) $< $(HYDE_O) $(LDFLAGS) -o $@

clean:
	rm -f $(PROGS) $(HYDE_O)
