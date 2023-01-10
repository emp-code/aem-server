#ifndef AEM_INTCOM_SERVER_H
#define AEM_INTCOM_SERVER_H

#include "KeyBundle.h"

void intcom_setKeys_server(const unsigned char newKeys[AEM_INTCOM_CLIENT_COUNT][crypto_secretbox_KEYBYTES]);
void tc_term(void);
void takeConnections(void);

#endif
