CFLAGS = -o p67 -O3 -I/usr/local/include -Wl,-rpath="/usr/local/lib"
COUNT_FLAGS = -D COUNT_KEYS=1
DEBUG_FLAGS = -g -D DEBUG=1
LDFLAGS = -L/usr/local/lib
LDLIBS = -lpthread -lsecp256k1 -lssl -lcrypto
SRC = main.c ripemd160.c
release: 
	cc $(CFLAGS) $(SRC) $(LDFLAGS) $(LDLIBS)
debug:
	cc $(CFLAGS) $(DEBUG_FLAGS) $(SRC) $(LDFLAGS) $(LDLIBS)
count:
	cc $(CFLAGS) $(COUNT_FLAGS) $(SRC) $(LDFLAGS) $(LDLIBS)

.PHONY: clean

clean:
	rm p67