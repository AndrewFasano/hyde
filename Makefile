# CFLAGS needs -fcoroutines if building with gcc, but we encountered internal compiler errors with GCC coroutines so we use clang instead
CXX=clang++-15
CFLAGS=-g -I../hyde-qemu/hyde/include/ -I./sdk/ -std=c++20 -Wno-deprecated-declarations -fPIC
SO_CFLAGS=-fPIC -shared $(CFLAGS)
LDFLAGS=-fuse-ld=lld

SRCS = $(wildcard hyde_programs/*.cpp)
PROGS = $(patsubst %.cpp,%.so,$(SRCS))

HYDE = $(wildcard sdk/*.cpp)
HYDE_O = $(patsubst %.cpp,%.o,$(HYDE))
HYDE_H = $(wildcard sdk/*.h) $(wildcard sdk/*.tpp)

all: $(PROGS)

hyde_programs/gdbserver.o: hyde_programs/gdbserver.cpp
	$(CXX) $(CFLAGS) -c $< -o $@

sdk/%.o: sdk/%.cpp $(HYDE_H)
	$(CXX) $(CFLAGS) -c $< -o $@

# Pwreset needs link with crypt
hyde_programs/pwreset.so: hyde_programs/pwreset.cpp $(HYDE_O) $(HYDE_H)
	$(CXX) $(SO_CFLAGS) $< $(LDFLAGS) $(HYDE_O) -lcrypt -o $@

# Normal programs just link against hyde
hyde_programs/%.so : hyde_programs/%.cpp $(HYDE_O) $(HYDE_H)
	$(CXX) $(SO_CFLAGS) $< $(HYDE_O) $(LDFLAGS) -o $@

clean:
	rm -f $(PROGS) $(HYDE_O)
