#ifndef AEM_INTCOM_STREAMCLIENT_H
#define AEM_INTCOM_STREAMCLIENT_H

#include <sodium.h>

void intcom_setKey_stream(const unsigned char newKey[crypto_secretstream_xchacha20poly1305_KEYBYTES]);
void intcom_setPid_stream(const pid_t pid);

int intcom_stream_open(void);
int intcom_stream_send(const unsigned char * const src, const size_t lenSrc);
int32_t intcom_stream_end(void);

#endif
