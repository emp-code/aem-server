CC=gcc
CFLAGS=-O2 -march=native -pipe -std=gnu2x -Wall -Wextra -Wpedantic -Wno-comment -D_GNU_SOURCE -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fcf-protection=full -fPIE -pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack -Werror=incompatible-pointer-types -Werror=implicit-function-declaration -Werror=discarded-array-qualifiers -Werror=alloc-zero -Wbidi-chars=any  -Wduplicated-branches -Wfloat-equal -Wshadow -Wbad-function-cast -Wcast-qual -Wcast-align -Wlogical-op -Wmissing-declarations -Winvalid-utf8 -Wpadded -Wredundant-decls -Wstrict-prototypes -Wunused-macros -Wwrite-strings -Wpointer-arith -Wstack-usage=999999 -Wtrampolines -fanalyzer -Wformat=0

all: aem-manager aem-account aem-deliver aem-enquiry aem-storage aem-mta aem-web aem-api utils/BinCrypt utils/Creator utils/ManagerClient Data/gen_dkim Data/gen_html Data/gen_tls

aem-manager: manager/*.c
	$(CC) $(CFLAGS) -DAEM_MANAGER -o aem-manager manager/*.c Common/AEM_KDF.c Common/CreateSocket.c Common/GetKey.c Common/ToggleEcho.c Common/ValidFd.c Common/memeq.c -lsodium -lcap

aem-account: account/*.c
	$(CC) $(CFLAGS) -DAEM_ACCOUNT -o aem-account account/*.c Common/AEM_KDF.c Common/SetCaps.c Common/memeq.c IntCom/Client.c IntCom/Server.c IntCom/peerok.c -lsodium -lcap -lm

aem-deliver: deliver/*.c
	$(CC) $(CFLAGS) -DAEM_DELIVER -o aem-deliver deliver/*.c Common/HtmlRefs.c Common/Html2Cet.c Common/QuotedPrintable.c Common/SetCaps.c Common/Signature.c Common/ToUtf8.c Common/Trim.c Common/ValidDomain.c Common/ValidUtf8.c Common/base64.c Common/memeq.c Common/ref2codepoint.c IntCom/Client.c IntCom/Stream_Server.c IntCom/peerok.c -lsodium -lcap -lbrotlienc -licuuc -licui18n -licudata -licui18n -lmbedtls -lmbedcrypto -lmbedx509

aem-enquiry: enquiry/*.c
	$(CC) $(CFLAGS) -DAEM_ENQUIRY -o aem-enquiry enquiry/*.c Common/SetCaps.c Common/ValidDomain.c Common/ValidIp.c Common/memeq.c IntCom/Server.c IntCom/peerok.c -lsodium -lcap -lmbedtls -lmbedcrypto -lmbedx509 -lmaxminddb

aem-storage: storage/*.c
	$(CC) $(CFLAGS) -DAEM_STORAGE -o aem-storage storage/*.c Common/AEM_KDF.c Common/Envelope.c Common/Message.c Common/Signature.c Common/SetCaps.c Common/memeq.c IntCom/Client.c IntCom/Server.c IntCom/peerok.c -lsodium -lcap

aem-api: api/*.c
	$(CC) $(CFLAGS) -DAEM_API -DAEM_LOCAL -o aem-api api/*.c Common/AEM_KDF.c Common/AcceptClients.c Common/Addr32.c Common/CreateSocket.c Common/Message.c Common/SetCaps.c Common/ValidDomain.c Common/ValidEmail.c Common/ValidUtf8.c Common/memeq.c IntCom/Client.c IntCom/peerok.c -lsodium -lcap -lmbedtls -lmbedcrypto -lmbedx509

aem-mta: mta/*.c
	$(CC) $(CFLAGS) -DAEM_MTA -o aem-mta mta/*.c Common/AcceptClients.c Common/Addr32.c Common/CreateSocket.c Common/SetCaps.c Common/memeq.c Common/ValidIp.c IntCom/Client.c IntCom/Stream_Client.c IntCom/peerok.c -lsodium -lcap -lmbedtls -lmbedcrypto -lmbedx509

aem-web: web/*.c
	$(CC) $(CFLAGS) -DAEM_WEB -o aem-web web/*.c Common/CreateSocket.c Common/SetCaps.c Common/memeq.c -lsodium -lcap

utils/BinCrypt: utils/BinCrypt.c
	$(CC) $(CFLAGS) -o utils/BinCrypt utils/BinCrypt.c Common/AEM_KDF.c Common/GetKey.c Common/ToggleEcho.c -lsodium

utils/ReadCrypt: utils/ReadCrypt.c
	$(CC) $(CFLAGS) -o utils/ReadCrypt utils/ReadCrypt.c Common/AEM_KDF.c Common/GetKey.c Common/ToggleEcho.c -lsodium

utils/Creator: utils/Creator.c
	$(CC) $(CFLAGS) -o utils/Creator Common/AEM_KDF.c Common/Envelope.c Common/Message.c Common/Signature.c utils/Creator.c Common/GetKey.c Common/ToggleEcho.c Common/memeq.c -lsodium

utils/ManagerClient: utils/ManagerClient.c
	$(CC) $(CFLAGS) -o utils/ManagerClient utils/ManagerClient.c Common/AEM_KDF.c Common/GetKey.c Common/ToggleEcho.c -lsodium

Data/gen_dkim: Data/gen_dkim.c
	$(CC) $(CFLAGS) -o Data/gen_dkim Data/gen_dkim.c

Data/gen_html: Data/gen_html.c
	$(CC) $(CFLAGS) -o Data/gen_html Data/gen_html.c Common/GetKey.c Common/Brotli.c Common/ToggleEcho.c -lsodium -lbrotlienc -lzopfli

Data/gen_tls: Data/gen_tls.c
	$(CC) $(CFLAGS) -o Data/gen_tls Data/gen_tls.c Common/memeq.c

.PHONY: clean
clean:
	-rm aem-manager aem-account aem-deliver aem-enquiry aem-storage aem-mta aem-web aem-api utils/BinCrypt utils/ManagerClient Data/gen_dkim Data/gen_html Data/gen_tls
