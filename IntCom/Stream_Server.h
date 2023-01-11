#ifndef AEM_INTCOM_STREAMSERVER_H
#define AEM_INTCOM_STREAMSERVER_H

void intcom_setKey_stream(const unsigned char newKey[crypto_secretstream_xchacha20poly1305_KEYBYTES]);
void sigTerm();
void takeConnections(void);

#endif
