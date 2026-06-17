CC=gcc
CFLAGS=-O2 -march=native -pipe -std=gnu23 -D_GNU_SOURCE -D_FORTIFY_SOURCE=2 -fPIE -pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack -fanalyzer -fcf-protection=full -fstack-protector-strong -Wall -Wextra -Wpedantic -Werror=alloc-zero -Werror=analyzer-out-of-bounds -Werror=discarded-array-qualifiers -Werror=implicit-function-declaration -Werror=incompatible-pointer-types -Werror=int-conversion -Werror=nonnull -Werror=parentheses -Werror=return-type -Werror=shadow -Werror=strict-aliasing -Wbad-function-cast -Wbidi-chars=any -Wcast-align -Wcast-qual -Wduplicated-branches -Wfloat-equal -Wformat=0 -Winvalid-utf8 -Wlogical-op -Wmissing-declarations -Wpointer-arith -Wredundant-decls -Wstrict-prototypes -Wtrampolines -Wunused-macros -Wwrite-strings -Wno-comment

all: aem-manager aem-acc aem-dlv aem-enq aem-sto aem-api aem-mta aem-reg aem-web utils/AdminAddr utils/BinCrypt utils/Creator utils/DataCrypt utils/WebMaker

aem-manager: manager/*.c
	$(CC) $(CFLAGS) -DAEM_MANAGER -o aem-manager -DAEM_UDS -Wno-analyzer-fd-use-after-close -Wno-analyzer-fd-leak -Wno-analyzer-fd-double-close manager/*.c Common/AEM_KDF.c Common/AcceptClients.c Common/CreateSocket.c Common/GetKey.c Common/ToggleEcho.c Common/ValidFd.c Common/memeq.c Common/x509_getCn.c -lcap -lsodium

aem-acc: account/*.c
	$(CC) $(CFLAGS) -DAEM_ACCOUNT -o aem-acc account/*.c Common/Addr32.c Common/AddrToHash.c Common/AEM_KDF.c Common/SetCaps.c Common/binTs.c Common/div_round.c Common/memeq.c IntCom/Client.c IntCom/Server.c IntCom/peerok.c -lcap -lsodium

aem-dlv: deliver/*.c
	$(CC) $(CFLAGS) -DAEM_DELIVER -o aem-dlv -Wno-analyzer-fd-leak -Wno-analyzer-fd-double-close deliver/*.c Common/Envelope.c Common/HtmlRefs.c Common/Html2Cet.c Common/Message.c Common/QuotedPrintable.c Common/SetCaps.c Common/ToUtf8.c Common/Trim.c Common/ValidDomain.c Common/ValidUtf8.c Common/base64.c Common/binTs.c Common/div_round.c Common/memeq.c Common/ref2codepoint.c IntCom/Client.c IntCom/Stream_Server.c IntCom/peerok.c -lbrotlienc -lcap -licudata -licui18n -licuuc -lsodium -lwolfssl

aem-enq: enquiry/*.c
	$(CC) $(CFLAGS) -DAEM_ENQUIRY -o aem-enq enquiry/*.c Common/SetCaps.c Common/ValidDomain.c Common/ValidIp.c Common/memeq.c IntCom/Server.c IntCom/peerok.c -lcap -lmaxminddb -lsodium

aem-sto: storage/*.c
	$(CC) $(CFLAGS) -DAEM_STORAGE -o aem-sto storage/*.c Common/AEM_KDF.c Common/Envelope.c Common/Message.c Common/Signature.c Common/SetCaps.c Common/binTs.c Common/div_round.c IntCom/Client.c IntCom/Server.c IntCom/peerok.c -lcap -lsodium -lwolfssl

aem-reg: reg/*.c
	$(CC) $(CFLAGS) -DAEM_REG -Wno-analyzer-fd-double-close -o aem-reg -DAEM_UDS reg/*.c Common/AcceptClients.c Common/CreateSocket.c Common/SetCaps.c Common/binTs.c Common/div_round.c IntCom/Client.c IntCom/peerok.c -lcap -lsodium

aem-web: web/*.c
	$(CC) $(CFLAGS) -DAEM_WEB -o aem-web -DAEM_UDS web/*.c Common/CreateSocket.c Common/SetCaps.c -lcap -lsodium

aem-api: api/*.c
	$(CC) $(CFLAGS) -DAEM_API -Wno-analyzer-fd-double-close -o aem-api -DAEM_UDS api/*.c Common/AEM_KDF.c Common/AcceptClients.c Common/Addr32.c Common/CreateSocket.c Common/Message.c Common/SetCaps.c Common/ValidDomain.c Common/ValidEmail.c Common/ValidUtf8.c Common/binTs.c Common/div_round.c Common/memeq.c Common/x509_getCn.c IntCom/Client.c IntCom/peerok.c -lcap -lsodium -lwolfssl

aem-mta: mta/*.c
	$(CC) $(CFLAGS) -DAEM_MTA -Wno-analyzer-fd-double-close -o aem-mta mta/*.c Common/AcceptClients.c Common/Addr32.c Common/CreateSocket.c Common/SetCaps.c Common/ValidIp.c Common/binTs.c Common/div_round.c Common/memeq.c Common/x509_getCn.c IntCom/Client.c IntCom/Stream_Client.c IntCom/peerok.c -lcap -lsodium -lwolfssl

utils/AdminAddr: utils/AdminAddr.c
	$(CC) $(CFLAGS) -o utils/AdminAddr utils/AdminAddr.c Common/Addr32.c

utils/BinCrypt: utils/BinCrypt.c
	$(CC) $(CFLAGS) -o utils/BinCrypt utils/BinCrypt.c Common/AEM_KDF.c Common/GetKey.c Common/ToggleEcho.c -lsodium

utils/Creator: utils/Creator.c
	$(CC) $(CFLAGS) -o utils/Creator -DAEM_KDF_UMK utils/Creator.c Common/AddrToHash.c Common/AEM_KDF.c Common/Envelope.c Common/Message.c Common/Signature.c Common/GetKey.c Common/ToggleEcho.c Common/binTs.c Common/div_round.c Common/memeq.c -lsodium -lwolfssl

utils/DataCrypt: utils/DataCrypt.c
	$(CC) $(CFLAGS) -o utils/DataCrypt utils/DataCrypt.c Common/AEM_KDF.c Common/GetKey.c Common/ToggleEcho.c -lsodium

utils/WebMaker: utils/WebMaker.c
	$(CC) $(CFLAGS) -o utils/WebMaker utils/WebMaker.c Common/AEM_KDF.c Common/GetKey.c Common/ToggleEcho.c -lbrotlienc -lsodium

.PHONY: clean
clean:
	-rm aem-manager aem-acc aem-dlv aem-enq aem-sto aem-api aem-mta aem-reg aem-web utils/BinCrypt utils/Creator utils/DataCrypt utils/WebMaker
