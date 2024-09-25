release:
	cc main.c ripemd160.c -o p67 -O3 -Wl,-rpath="/usr/local/lib" -lpthread -lsecp256k1 -lssl -lcrypto

debug:
	cc -g main.c ripemd160.c -o p67 -O3 -D DEBUG=1 -Wl,-rpath="/usr/local/lib" -lpthread -lsecp256k1 -lssl -lcrypto

count:
	cc main.c ripemd160.c -o p67 -O3 -D COUNT_KEYS=1 -Wl,-rpath="/usr/local/lib" -lpthread -lsecp256k1 -lssl -lcrypto


.PHONY: clean

clean:
	rm p67