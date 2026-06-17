#ifndef AEM_ENVELOPE_H
#define AEM_ENVELOPE_H

#include <stdint.h>

#include "../Global.h"
#include "evpKeys.h"

uint16_t getEnvelopeId(const unsigned char * const src);
unsigned char *msg2evp(unsigned char * const msg, const size_t lenMsg, const unsigned char epk[AEM_EPK_KEYLEN], const uint16_t * const usedIds, const int usedIdCount, size_t * const lenEvp);

#endif
