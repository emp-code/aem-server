#ifndef AEM_ENVELOPE_H
#define AEM_ENVELOPE_H

#include "../Global.h"

void message_into_envelope(unsigned char * const target, const int lenTarget, const unsigned char epk[X25519_PKBYTES]);

#endif
