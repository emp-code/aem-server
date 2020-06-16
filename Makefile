CC=gcc
CFLAGS=-g -O1 -march=native -pipe -Wall -Wextra -Werror -Wno-comment -D_FORTIFY_SOURCE=2 -fsanitize=undefined -fstack-protector-strong -fcf-protection=full -fPIE -pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack -Wno-error=unused-result  -Wno-error=unused-function -Wno-error=unused-parameter -Wno-error=unused-variable

all: aem-manager aem-account aem-enquiry aem-storage aem-api aem-web aem-mta utils/Accgen utils/CertCrypt utils/HtmlCrypt utils/Keygen utils/ManagerClient utils/Resgen

aem-manager: manager/*.c
	$(CC) $(CFLAGS) -o aem-manager manager/*.c -lsodium -lcap

aem-account: account/*.c
	$(CC) $(CFLAGS) -o aem-account account/*.c -lsodium

aem-enquiry: enquiry/*.c
	$(CC) $(CFLAGS) -o aem-enquiry enquiry/*.c -lsodium -lsodium -lmbedtls -lmbedcrypto -lmbedx509

aem-storage: storage/*.c
	$(CC) $(CFLAGS) -o aem-storage storage/*.c -lsodium

aem-api: api/*.c
	$(CC) $(CFLAGS) -o aem-api api/*.c api/Include/*.c -lsodium -lmbedtls -lmbedcrypto -lmbedx509 -lcap

aem-web: web/*.c
	$(CC) $(CFLAGS) -o aem-web web/*.c web/Include/*.c -lsodium -lmbedtls -lmbedcrypto -lmbedx509 -lcap

aem-mta: mta/*.c
	$(CC) $(CFLAGS) -o aem-mta mta/*.c mta/Include/*.c -lsodium -lmbedtls -lmbedcrypto -lmbedx509 -lcap -lbrotlienc -lmaxminddb -licuuc -licui18n

utils/Accgen: utils/Accgen.c
	$(CC) $(CFLAGS) -o utils/Accgen utils/Accgen.c utils/GetKey.c -lsodium

utils/CertCrypt: utils/CertCrypt.c
	$(CC) $(CFLAGS) -o utils/CertCrypt utils/CertCrypt.c utils/GetKey.c -lsodium

utils/HtmlCrypt: utils/HtmlCrypt.c
	$(CC) $(CFLAGS) -o utils/HtmlCrypt utils/HtmlCrypt.c utils/GetKey.c -lsodium -lbrotlienc

utils/Keygen: utils/Keygen.c
	$(CC) $(CFLAGS) -o utils/Keygen utils/Keygen.c -lsodium

utils/ManagerClient: utils/ManagerClient.c
	$(CC) $(CFLAGS) -o utils/ManagerClient utils/ManagerClient.c utils/GetKey.c -lsodium

utils/Resgen: utils/Resgen.c
	$(CC) $(CFLAGS) -o utils/Resgen utils/Resgen.c utils/GetKey.c -lsodium

.PHONY: clean
clean:
	-rm aem-manager aem-account aem-enquiry aem-storage aem-api aem-web aem-mta utils/Accgen utils/CertCrypt utils/HtmlCrypt utils/Keygen utils/ManagerClient utils/Resgen
