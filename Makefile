CC=gcc
CFLAGS=-g -march=native -pipe -Wall -Werror=array-bounds -Werror=format-overflow=0 -Werror=format -Werror=implicit-function-declaration -Werror=implicit-int -Werror=incompatible-pointer-types -Wno-comment -Wno-switch -Wno-unused-variable
objects = main.o http.o https.o smtp.o Includes/b64dec.o

ae-mail: $(objects)
	$(CC) $(CFLAGS) -o ae-mail $(objects) -lnacl -lmbedtls -lmbedcrypto -lmbedx509

main: main.c http.h https.h

Includes/b64dec.o: Includes/b64dec.c

http.o: http.c
https.o: https.c Includes/b64dec.h

.PHONY: clean
clean:
	-rm $(objects)
