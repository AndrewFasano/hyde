# CFLAGS needs -fcoroutines if building with gcc. But the internet claims
# gcc is terrible with coroutines. Not sure if I believe that, but
# I'm getting internal compiler errors now so let's give clang a shot!

CXX=clang++-15
CFLAGS=-g -I../qemu/accel/kvm/ -I./hyde/ -std=c++20
SO_CFLAGS=-fPIC -shared $(CFLAGS)
LDFLAGS=


SRCS = $(wildcard caps/*.cpp)
PROGS = $(patsubst %.cpp,%.so,$(SRCS))

HYDE = $(wildcard hyde/*.cpp)
HYDE_O = $(patsubst %.cpp,%.o,$(HYDE))

all: $(PROGS)

test: test.cpp
	$(CXX) $(CFLAGS) $< -o $@

$(HYDE_O): $(HYDE)
	$(CXX) $(CFLAGS) -c $< -o $@

# Pwreset needs link with crypt
caps/pwreset.so: caps/pwreset.cpp  $(HYDE_O)
	$(CXX) $(SO_CFLAGS) $< $(LDFLAGS) $(HYDE_O) -lcrypt -o $@

# Hyperptrace needs link with pthread
caps/hyperptrace.so: caps/hyperptrace.cpp $(HYDE_O)
	$(CXX) $(SO_CFLAGS) $< $(HYDE_O) $(LDFLAGS) -lpthread -o $@

# Normal programs
caps/%.so : caps/%.cpp $(HYDE_O)
	$(CXX) $(SO_CFLAGS) $< $(HYDE_O) $(LDFLAGS) -o $@

clean:
	rm -f $(PROGS) $(HYDE_P)
