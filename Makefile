CC=gcc
CFLAGS=-O2 -march=native -pipe -Wall -Wextra -Wno-comment -D_GNU_SOURCE -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fcf-protection=full -fPIE -pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack -Werror=incompatible-pointer-types -Werror=implicit-function-declaration -Werror=discarded-array-qualifiers

all: aem-manager aem-account aem-deliver aem-enquiry aem-storage aem-mta aem-web-clr aem-web-oni aem-api-clr aem-api-oni utils/BinCrypt utils/ManagerClient Data/gen_address Data/gen_dkim Data/gen_html Data/gen_tls

aem-manager: manager/*.c
	$(CC) $(CFLAGS) -DAEM_MANAGER -o aem-manager manager/*.c Common/CreateSocket.c Common/GetKey.c Common/ToggleEcho.c Common/ValidFd.c Common/memeq.c -lsodium -lcap

aem-account: account/*.c
	$(CC) $(CFLAGS) -DAEM_ACCOUNT -o aem-account account/*.c Common/SetCaps.c Common/memeq.c IntCom/Client.c IntCom/Server.c -lsodium -lcap -lm

aem-enquiry: enquiry/*.c
	$(CC) $(CFLAGS) -DAEM_ENQUIRY -o aem-enquiry enquiry/*.c Common/SetCaps.c Common/ValidDomain.c Common/ValidIp.c Common/memeq.c IntCom/Server.c -lsodium -lcap -lmbedtls -lmbedcrypto -lmbedx509 -lmaxminddb

aem-storage: storage/*.c
	$(CC) $(CFLAGS) -DAEM_STORAGE -o aem-storage storage/*.c Common/SetCaps.c Common/aes.c Common/memeq.c IntCom/Server.c -lsodium -lcap

aem-web-clr: web-clr/*.c
	$(CC) $(CFLAGS) -DAEM_WEB -DAEM_WEB_CLR -o aem-web-clr web-clr/*.c Common/tls_common.c Common/AcceptClients.c Common/CreateSocket.c Common/SetCaps.c Common/memeq.c -lsodium -lcap -lmbedtls -lmbedcrypto -lmbedx509

aem-web-oni: web-oni/main.c
	$(CC) $(CFLAGS) -DAEM_WEB -DAEM_WEB_ONI -DAEM_IS_ONION -o aem-web-oni web-oni/main.c Common/SetCaps.c Common/CreateSocket.c Common/memeq.c -lsodium -lcap

aem-api-clr: api/*.c
	$(CC) $(CFLAGS) -DAEM_API_CLR -DAEM_API -o aem-api-clr api/*.c Common/AcceptClients.c Common/Addr32.c Common/CreateSocket.c Common/SetCaps.c Common/ValidDomain.c Common/ValidEmail.c Common/ValidUtf8.c Common/aes.c Common/memeq.c Common/tls_common.c IntCom/Client.c -lsodium -lcap -lmbedtls -lmbedcrypto -lmbedx509

aem-api-oni: api/*.c
	$(CC) $(CFLAGS) -DAEM_API_ONI -DAEM_API -DAEM_IS_ONION -o aem-api-oni api/*.c Common/AcceptClients.c Common/Addr32.c Common/CreateSocket.c Common/SetCaps.c Common/ValidDomain.c Common/ValidEmail.c Common/ValidUtf8.c Common/aes.c Common/memeq.c IntCom/Client.c -lsodium -lcap -lmbedtls -lmbedcrypto -lmbedx509

aem-deliver: deliver/*.c
	$(CC) $(CFLAGS) -DAEM_DELIVER -o aem-deliver deliver/*.c Common/HtmlRefs.c Common/HtmlToText.c Common/QuotedPrintable.c Common/SetCaps.c Common/ToUtf8.c Common/Trim.c Common/ValidDomain.c Common/ValidUtf8.c Common/memeq.c Common/ref2codepoint.c IntCom/Client.c IntCom/Stream_Server.c -lsodium -lcap -lbrotlienc -licuuc -licui18n -licudata -licui18n -lmbedtls -lmbedcrypto -lmbedx509

aem-mta: mta/*.c
	$(CC) $(CFLAGS) -DAEM_MTA -o aem-mta mta/*.c Common/AcceptClients.c Common/Addr32.c Common/CreateSocket.c Common/SetCaps.c Common/memeq.c Common/ValidIp.c IntCom/Client.c IntCom/Stream_Client.c -lsodium -lcap -lmbedtls -lmbedcrypto -lmbedx509

utils/BinCrypt: utils/BinCrypt.c
	$(CC) $(CFLAGS) -o utils/BinCrypt utils/BinCrypt.c Common/GetKey.c Common/ToggleEcho.c -lsodium

utils/ManagerClient: utils/ManagerClient.c
	$(CC) $(CFLAGS) -o utils/ManagerClient utils/ManagerClient.c Common/GetKey.c Common/ToggleEcho.c -lsodium

Data/gen_address: Data/gen_address.c
	$(CC) $(CFLAGS) -o Data/gen_address Data/gen_address.c -lsodium

Data/gen_html: Data/gen_html.c
	$(CC) $(CFLAGS) -o Data/gen_html Data/gen_html.c Common/GetKey.c Common/Brotli.c Common/ToggleEcho.c -lsodium -lbrotlienc -lzopfli

Data/gen_dkim: Data/gen_dkim.c
	$(CC) $(CFLAGS) -o Data/gen_dkim Data/gen_dkim.c

Data/gen_tls: Data/gen_tls.c
	$(CC) $(CFLAGS) -o Data/gen_tls Data/gen_tls.c Common/memeq.c

.PHONY: clean
clean:
	-rm aem-manager aem-account aem-deliver aem-enquiry aem-storage aem-mta aem-web-clr aem-web-oni aem-api-clr aem-api-oni utils/BinCrypt utils/ManagerClient Data/gen_address Data/gen_dkim Data/gen_html Data/gen_tls
