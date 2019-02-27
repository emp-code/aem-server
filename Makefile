CC=gcc
CFLAGS=-O3 -march=native -pipe -Wall -Werror=array-bounds -Werror=format-overflow=0 -Werror=format -Werror=implicit-function-declaration -Werror=implicit-int -Werror=incompatible-pointer-types -Wno-comment -Wno-switch -Wno-unused-variable -lmbedtls -lmbedcrypto -lmbedx509
objects = main.o http.o https.o smtp.o

ae-mail: $(objects)
	$(CC) $(CFLAGS) -o ae-mail $(objects)

main: main.c http.h

http.o: http.c

.PHONY: clean
clean:
	-rm $(objects)
