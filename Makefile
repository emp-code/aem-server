CC=gcc
CFLAGS=-g -O1 -march=native -pipe -Wall -Wextra -Werror -Wno-comment -D_FORTIFY_SOURCE=2 -fsanitize=undefined -fstack-protector-strong -fcf-protection=full -fPIE -pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack -Wno-error=unused-result  -Wno-error=unused-function

all: allears-manager allears-api allears-web allears-mta

allears-manager: manager/*.c
	$(CC) $(CFLAGS) -o allears-manager manager/*.c -lsodium -lcap

allears-account: account/*.c
	$(CC) $(CFLAGS) -o allears-account account/*.c -lsodium

allears-api: api/*.c
	$(CC) $(CFLAGS) -o allears-api api/*.c api/Include/*.c -lsodium -lmbedtls -lmbedcrypto -lmbedx509 -lcap

allears-web: web/*.c
	$(CC) $(CFLAGS) -o allears-web web/*.c web/Include/*.c -lsodium -lmbedtls -lmbedcrypto -lmbedx509 -lcap

allears-mta: mta/*.c
	$(CC) $(CFLAGS) -o allears-mta mta/*.c mta/Include/*.c -lsodium -lmbedtls -lmbedcrypto -lmbedx509 -lsqlite3 -lbrotlienc -lmaxminddb -licuuc -licui18n

.PHONY: clean
clean:
	-rm allears-manager allears-api allears-web allears-mta

