CC=gcc
CFLAGS=-O1 -g -march=native -pipe -Wall -Wextra -Wno-comment -D_GNU_SOURCE -D_FORTIFY_SOURCE=2 -fsanitize=undefined -fstack-protector-strong -fcf-protection=full -fPIE -pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack -Werror=incompatible-pointer-types -Werror=implicit-function-declaration
all: aem-manager aem-account aem-enquiry aem-storage aem-mta aem-web-clr aem-web-oni aem-api-clr aem-api-oni utils/Accgen utils/CertCrypt utils/FileCrypt utils/Keygen utils/ManagerClient utils/Resgen

aem-manager: manager/*.c
	$(CC) $(CFLAGS) -o aem-manager manager/*.c Common/CreateSocket.c Common/ToggleEcho.c -lsodium -lcap -lmbedcrypto -lmbedx509 -lbrotlienc -lzopfli

aem-account: account/*.c
	$(CC) $(CFLAGS) -o aem-account account/*.c Common/SetCaps.c -lsodium -lcap

aem-enquiry: enquiry/*.c
	$(CC) $(CFLAGS) -o aem-enquiry enquiry/*.c Common/SetCaps.c -lsodium -lcap -lmbedtls -lmbedcrypto -lmbedx509

aem-storage: storage/*.c
	$(CC) $(CFLAGS) -o aem-storage storage/*.c Common/SetCaps.c Common/aes.c -lsodium -lcap

aem-web-clr: web-clr/*.c
	$(CC) $(CFLAGS) -o aem-web-clr web-clr/*.c Common/tls_common.c Common/CreateSocket.c Common/SetCaps.c -lsodium -lcap -lmbedtls -lmbedcrypto -lmbedx509

aem-web-oni: web-oni/main.c
	$(CC) $(CFLAGS) -o aem-web-oni web-oni/main.c Common/SetCaps.c Common/CreateSocket.c -lsodium -lcap

aem-api-clr: api-clr/*.c
	$(CC) $(CFLAGS) -o aem-api-clr api-clr/*.c api-common/*.c Common/Addr32.c Common/CreateSocket.c Common/SetCaps.c Common/aes.c Common/tls_common.c -lsodium -lcap -lmbedtls -lmbedcrypto -lmbedx509

aem-api-oni: api-oni/*.c
	$(CC) $(CFLAGS) -DAEM_IS_ONION -o aem-api-oni api-oni/*.c api-common/*.c Common/Addr32.c Common/CreateSocket.c Common/SetCaps.c Common/aes.c -lsodium -lcap -lmbedtls -lmbedcrypto -lmbedx509

aem-mta: mta/*.c
	$(CC) $(CFLAGS) -o aem-mta mta/*.c Common/SetCaps.c Common/Addr32.c Common/Base64.c Common/Brotli.c Common/CreateSocket.c Common/HtmlToText.c Common/QuotedPrintable.c Common/ToUtf8.c Common/Trim.c -lsodium -lcap -lmbedtls -lmbedcrypto -lmbedx509 -lbrotlienc -lmaxminddb -licuuc -licui18n

utils/Accgen: utils/Accgen.c
	$(CC) $(CFLAGS) -o utils/Accgen utils/Accgen.c utils/GetKey.c Common/ToggleEcho.c -lsodium

utils/CertCrypt: utils/CertCrypt.c
	$(CC) $(CFLAGS) -o utils/CertCrypt utils/CertCrypt.c utils/GetKey.c Common/ToggleEcho.c -lsodium

utils/FileCrypt: utils/FileCrypt.c
	$(CC) $(CFLAGS) -o utils/FileCrypt utils/FileCrypt.c utils/GetKey.c Common/ToggleEcho.c -lsodium -lbrotlienc

utils/Keygen: utils/Keygen.c
	$(CC) $(CFLAGS) -o utils/Keygen utils/Keygen.c -lsodium

utils/ManagerClient: utils/ManagerClient.c
	$(CC) $(CFLAGS) -o utils/ManagerClient utils/ManagerClient.c utils/GetKey.c Common/ToggleEcho.c -lsodium

utils/Resgen: utils/Resgen.c
	$(CC) $(CFLAGS) -o utils/Resgen utils/Resgen.c utils/GetKey.c Common/ToggleEcho.c -lsodium

.PHONY: clean
clean:
	-rm aem-manager aem-account aem-enquiry aem-storage aem-mta aem-web-clr aem-web-oni aem-api-clr aem-api-oni utils/Accgen utils/CertCrypt utils/FileCrypt utils/Keygen utils/ManagerClient utils/Resgen
