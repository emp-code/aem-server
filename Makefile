CC=gcc
CFLAGS=-O1 -g -march=native -pipe -Wall -Wextra -Wno-comment -D_GNU_SOURCE -D_FORTIFY_SOURCE=2 -fsanitize=undefined -fstack-protector-strong -fcf-protection=full -fPIE -pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack -Wno-error=unused-result  -Wno-error=unused-function -Wno-error=unused-parameter -Wno-error=unused-variable

all: aem-manager aem-account aem-enquiry aem-storage aem-api aem-web aem-web-oni aem-mta utils/Accgen utils/CertCrypt utils/FileCrypt utils/Keygen utils/ManagerClient utils/Resgen

aem-manager: manager/*.c
	$(CC) $(CFLAGS) -o aem-manager manager/*.c Common/ToggleEcho.c -lsodium -lcap -lmbedcrypto -lmbedx509 -lbrotlienc -lz

aem-account: account/*.c
	$(CC) $(CFLAGS) -o aem-account account/*.c Common/SetCaps.c -lsodium -lcap

aem-enquiry: enquiry/*.c
	$(CC) $(CFLAGS) -o aem-enquiry enquiry/*.c Common/SetCaps.c -lsodium -lcap -lmbedtls -lmbedcrypto -lmbedx509

aem-storage: storage/*.c
	$(CC) $(CFLAGS) -o aem-storage storage/*.c Common/SetCaps.c -lsodium -lcap

aem-api: api/*.c
	$(CC) $(CFLAGS) -o aem-api api/*.c api/Include/*.c Common/SetCaps.c -lsodium -lmbedtls -lmbedcrypto -lmbedx509 -lcap

aem-web: web/*.c
	$(CC) $(CFLAGS) -o aem-web web/*.c web/Include/*.c Common/SetCaps.c -lsodium -lmbedtls -lmbedcrypto -lmbedx509 -lcap

aem-web-oni: web-oni/main.c
	$(CC) $(CFLAGS) -o aem-web-oni web-oni/main.c -lsodium

aem-mta: mta/*.c
	$(CC) $(CFLAGS) -o aem-mta mta/*.c mta/Include/*.c Common/SetCaps.c -lsodium -lmbedtls -lmbedcrypto -lmbedx509 -lcap -lbrotlienc -lmaxminddb -licuuc -licui18n

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
	-rm aem-manager aem-account aem-enquiry aem-storage aem-api aem-web aem-mta utils/Accgen utils/CertCrypt utils/FileCrypt utils/Keygen utils/ManagerClient utils/Resgen
