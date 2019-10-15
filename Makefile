CC=gcc
CFLAGS=-g -O1 -march=native -pipe -Wall -Wextra -Werror -Wno-comment -D_FORTIFY_SOURCE=2 -fsanitize=undefined -fstack-protector-strong -fcf-protection=full -fPIE -pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack -Wno-error=unused-result
objects = main.o Database.o Message.o https.o https_common.o https_get.o https_post.o smtp.o Includes/Addr32.o Includes/Base64.o Includes/Brotli.o Includes/CharToInt64.o Includes/QuotedPrintable.o

ae-mail: $(objects)
	$(CC) $(CFLAGS) -o ae-mail $(objects) -lsodium -lmbedtls -lmbedcrypto -lmbedx509 -lbrotlienc -lsqlite3 -lmaxminddb

main: main.c https.h smpt.h

Includes/Addr32.o: Includes/Addr32.c
Includes/Base64.o: Includes/Base64.c
Includes/Brotli.o: Includes/Brotli.c
Includes/CharToInt64.o: Includes/CharToInt64.c
Includes/QuotedPrintable.o: Includes/QuotedPrintable.c

Database.o: Database.c Includes/CharToInt64.h Message.h
Message.o: Message.c
https.o: https.c https_get.h https_post.h
https_common.o: https_common.c
https_get.o: https_get.c https_common.h
https_post.o: https_post.c https_common.h Includes/Addr32.h Includes/CharToInt64.h Database.h Message.h
smtp.o: smtp.c Includes/Addr32.h Includes/Base64.h Includes/Brotli.h Includes/CharToInt64.h Includes/QuotedPrintable.h Database.h Message.h

.PHONY: clean
clean:
	-rm $(objects)
