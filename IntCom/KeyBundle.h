#ifndef AEM_INTCOM_KEYBUNDLE_H
#define AEM_INTCOM_KEYBUNDLE_H

#include <sodium.h>

typedef enum {
	AEM_INTCOM_CLIENT_ACC,
	AEM_INTCOM_CLIENT_API,
	AEM_INTCOM_CLIENT_MTA,
	AEM_INTCOM_CLIENT_REG,
	AEM_INTCOM_CLIENT_STO,
	AEM_INTCOM_CLIENT_COUNT
} aem_intcom_client_t;
#define AEM_INTCOM_CLIENT_DLV AEM_INTCOM_CLIENT_MTA // No process needs both

typedef enum { // Excludes Deliver, which uses IntCom_Stream
	AEM_INTCOM_SERVER_ACC,
	AEM_INTCOM_SERVER_ENQ,
	AEM_INTCOM_SERVER_STO,
	AEM_INTCOM_SERVER_COUNT
} aem_intcom_server_t;

struct intcom_keyBundle {
	unsigned char client[AEM_INTCOM_SERVER_COUNT][crypto_aead_aegis256_KEYBYTES]; // Client's keys for each server
	unsigned char server[AEM_INTCOM_CLIENT_COUNT][crypto_aead_aegis256_KEYBYTES]; // Server's keys for each client
	unsigned char stream[crypto_secretstream_xchacha20poly1305_KEYBYTES];
};

#endif
