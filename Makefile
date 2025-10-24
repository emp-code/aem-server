CC=gcc
CFLAGS=-O2 -march=native -pipe -std=gnu23 -Wall -Wextra -Wpedantic -Wno-comment -D_GNU_SOURCE -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fcf-protection=full -fPIE -pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack -Werror=alloc-zero -Werror=discarded-array-qualifiers -Werror=implicit-function-declaration -Werror=incompatible-pointer-types -Werror=int-conversion -Werror=nonnull -Werror=return-type -Werror=parentheses -Werror=shadow -Werror=strict-aliasing -Wbad-function-cast -Wbidi-chars=any -Wcast-align -Wcast-qual -Wduplicated-branches -Wfloat-equal -Winvalid-utf8 -Wlogical-op -Wmissing-declarations -Wpadded -Wpointer-arith -Wredundant-decls -Wstack-usage=999999 -Wstrict-prototypes -Wtrampolines -Wunused-macros -Wwrite-strings -fanalyzer -Wformat=0

all: aem-manager aem-account aem-deliver aem-enquiry aem-storage aem-api-tcp aem-api-uds aem-mta aem-reg aem-web-clr aem-web-oni utils/AdminAddr utils/BinCrypt utils/Creator utils/DataCrypt utils/ManagerClient utils/WebMaker

aem-manager: manager/*.c
	$(CC) $(CFLAGS) -DAEM_MANAGER -o aem-manager -Wno-analyzer-fd-use-after-close -Wno-analyzer-fd-leak -Wno-analyzer-fd-double-close manager/*.c Common/AEM_KDF.c Common/CreateSocket.c Common/GetKey.c Common/ToggleEcho.c Common/ValidFd.c Common/memeq.c Common/x509_getCn.c -lsodium -lcap

aem-account: account/*.c
	$(CC) $(CFLAGS) -DAEM_ACCOUNT -o aem-account account/*.c Common/Addr32.c Common/AddrToHash.c Common/AEM_KDF.c Common/SetCaps.c Common/binTs.c Common/memeq.c IntCom/Client.c IntCom/Server.c IntCom/peerok.c -lsodium -lcap -lm

aem-deliver: deliver/*.c
	$(CC) $(CFLAGS) -DAEM_DELIVER -o aem-deliver deliver/*.c Common/Envelope.c Common/HtmlRefs.c Common/Html2Cet.c Common/Message.c Common/QuotedPrintable.c Common/SetCaps.c Common/ToUtf8.c Common/Trim.c Common/ValidDomain.c Common/ValidUtf8.c Common/base64.c Common/binTs.c Common/memeq.c Common/ref2codepoint.c IntCom/Client.c IntCom/Stream_Server.c IntCom/peerok.c -lsodium -lcap -lbrotlienc -licuuc -licui18n -licudata -licui18n -lwolfssl -lm

aem-enquiry: enquiry/*.c
	$(CC) $(CFLAGS) -DAEM_ENQUIRY -o aem-enquiry enquiry/*.c Common/SetCaps.c Common/ValidDomain.c Common/ValidIp.c Common/memeq.c IntCom/Server.c IntCom/peerok.c -lsodium -lcap -lmaxminddb

aem-storage: storage/*.c
	$(CC) $(CFLAGS) -DAEM_STORAGE -o aem-storage storage/*.c Common/AEM_KDF.c Common/Envelope.c Common/Message.c Common/Signature.c Common/SetCaps.c Common/binTs.c Common/memeq.c IntCom/Client.c IntCom/Server.c IntCom/peerok.c -lsodium -lcap -lm

aem-api-tcp: api/*.c
	$(CC) $(CFLAGS) -DAEM_API -DAEM_API_TCP -DAEM_TLS -o aem-api-tcp api/*.c Common/AEM_KDF.c Common/AcceptClients.c Common/Addr32.c Common/CreateSocket.c Common/Message.c Common/SetCaps.c Common/ValidDomain.c Common/ValidEmail.c Common/ValidUtf8.c Common/binTs.c Common/memeq.c Common/x509_getCn.c IntCom/Client.c IntCom/peerok.c -lsodium -lcap -lwolfssl -lm

aem-api-uds: api/*.c
	$(CC) $(CFLAGS) -DAEM_API -DAEM_API_UDS -DAEM_UDS -o aem-api-uds api/*.c Common/AEM_KDF.c Common/AcceptClients.c Common/Addr32.c Common/CreateSocket.c Common/Message.c Common/SetCaps.c Common/ValidDomain.c Common/ValidEmail.c Common/ValidUtf8.c Common/binTs.c Common/memeq.c Common/x509_getCn.c IntCom/Client.c IntCom/peerok.c -lsodium -lcap -lwolfssl -lm

aem-mta: mta/*.c
	$(CC) $(CFLAGS) -DAEM_MTA -o aem-mta mta/*.c Common/AcceptClients.c Common/Addr32.c Common/CreateSocket.c Common/SetCaps.c Common/memeq.c Common/ValidIp.c Common/binTs.c Common/x509_getCn.c IntCom/Client.c IntCom/Stream_Client.c IntCom/peerok.c -lsodium -lcap -lwolfssl -lm

aem-reg: reg/*.c
	$(CC) $(CFLAGS) -DAEM_REG -o aem-reg reg/*.c Common/AcceptClients.c Common/CreateSocket.c Common/SetCaps.c Common/memeq.c Common/binTs.c IntCom/Client.c IntCom/peerok.c -lsodium -lcap -lwolfssl -lm

aem-web-clr: web/*.c
	$(CC) $(CFLAGS) -DAEM_WEB_CLR -DAEM_TLS -o aem-web-clr web/*.c Common/CreateSocket.c Common/SetCaps.c Common/memeq.c Common/x509_getCn.c -lsodium -lcap -lwolfssl

aem-web-oni: web/*.c
	$(CC) $(CFLAGS) -DAEM_WEB_ONI -DAEM_LOCAL -o aem-web-oni web/*.c Common/CreateSocket.c Common/SetCaps.c Common/memeq.c -lsodium -lcap

utils/AdminAddr: utils/AdminAddr.c
	$(CC) $(CFLAGS) -o utils/AdminAddr utils/AdminAddr.c Common/Addr32.c

utils/BinCrypt: utils/BinCrypt.c
	$(CC) $(CFLAGS) -o utils/BinCrypt utils/BinCrypt.c Common/AEM_KDF.c Common/GetKey.c Common/ToggleEcho.c -lsodium

utils/Creator: utils/Creator.c
	$(CC) $(CFLAGS) -o utils/Creator -DAEM_KDF_UMK utils/Creator.c Common/AddrToHash.c Common/AEM_KDF.c Common/Envelope.c Common/Message.c Common/Signature.c Common/GetKey.c Common/ToggleEcho.c Common/binTs.c Common/memeq.c -lsodium -lm

utils/DataCrypt: utils/DataCrypt.c
	$(CC) $(CFLAGS) -o utils/DataCrypt utils/DataCrypt.c Common/AEM_KDF.c Common/GetKey.c Common/ToggleEcho.c -lsodium

utils/ManagerClient: utils/ManagerClient.c
	$(CC) $(CFLAGS) -o utils/ManagerClient utils/ManagerClient.c Common/AEM_KDF.c Common/GetKey.c Common/ToggleEcho.c -lsodium

utils/WebMaker: utils/WebMaker.c
	$(CC) $(CFLAGS) -o utils/WebMaker utils/WebMaker.c Common/AEM_KDF.c Common/GetKey.c Common/ToggleEcho.c -lsodium -lbrotlienc

.PHONY: clean
clean:
	-rm aem-manager aem-account aem-deliver aem-enquiry aem-storage aem-api-tcp aem-api-uds aem-mta aem-reg aem-web-clr aem-web-oni utils/BinCrypt utils/Creator utils/DataCrypt utils/ManagerClient utils/WebMaker
