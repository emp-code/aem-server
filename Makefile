CC=gcc
CFLAGS=-g -O1 -march=native -pipe -Wall -Wextra -Werror -Wno-comment -D_FORTIFY_SOURCE=2 -fsanitize=undefined -fstack-protector-strong -fcf-protection=full -fPIE -pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack -Wno-error=unused-result

all: allears-api allears-web allears-smtp

allears-api: api/*.c
	$(CC) $(CFLAGS) -o allears-api api/*.c api/Include/*.c -lsodium -lmbedtls -lmbedcrypto -lmbedx509 -lsqlite3

allears-web: web/*.c
	$(CC) $(CFLAGS) -o allears-web web/*.c web/Include/*.c -lsodium -lmbedtls -lmbedcrypto -lmbedx509 -lbrotlienc

#allears-http: http/*.c
#	$(CC) $(CFLAGS) -o allears-http http/*.c

allears-smtp: smtp/*.c
	$(CC) $(CFLAGS) -o allears-smtp smtp/*.c smtp/Include/*.c -lsodium -lmbedtls -lmbedcrypto -lmbedx509 -lsqlite3 -lbrotlienc -lmaxminddb -licuuc -licui18n

.PHONY: clean
clean:
	-rm allears-api allears-web allears-smtp


