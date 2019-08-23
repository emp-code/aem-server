CC=gcc
CFLAGS=-g -O1 -march=native -pipe -Wall -Wextra -Werror -Wno-comment -Wno-unused-parameter -D_FORTIFY_SOURCE=2 -fsanitize=undefined -fstack-protector-strong -fcf-protection=full -fPIE -pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack -Wno-error=unused-result
objects = main.o http.o https.o smtp.o Includes/Base64.o Includes/Brotli.o Includes/QuotedPrintable.o Includes/SixBit.o Message.o Database.o

ae-mail: $(objects)
	$(CC) $(CFLAGS) -o ae-mail $(objects) -lsodium -lmbedtls -lmbedcrypto -lmbedx509 -lbrotlienc -lm -lsqlite3 -lmaxminddb

main: main.c http.h https.h smpt.h

Includes/Base64.o: Includes/Base64.c
Includes/Brotli.o: Includes/Brotli.c
Includes/QuotedPrintable.o: Includes/QuotedPrintable.c
Includes/SixBit.o: Includes/SixBit.c

Database.o: Database.c
Message.o: Message.c
http.o: http.c
https.o: https.c Includes/SixBit.h Database.h Message.h
smtp.o: smtp.c Includes/QuotedPrintable.h Includes/SixBit.h

.PHONY: clean
clean:
	-rm $(objects)
