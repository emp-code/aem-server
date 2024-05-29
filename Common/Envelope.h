#ifndef AEM_ENVELOPE_H
#define AEM_ENVELOPE_H

#include "../Global.h"

uint16_t getEnvelopeId(const unsigned char * const src);
void message_into_envelope(unsigned char * const target, const int lenTarget, const unsigned char epk[X25519_PKBYTES], const uint16_t * const usedIds, const int usedIdCount);

#endif
