#include <strings.h>
#include <string.h>
#include <time.h>

#include "../Global.h"

#include "Message.h"

void aem_msg_init(unsigned char * const msg, const int type, uint64_t ts) {
	// Signature (set by AEM-Storage)
	bzero(msg, AEM_MSG_HDR_SZ - sizeof(uint32_t));

	// Type
	msg[AEM_MSG_HDR_SZ - sizeof(uint32_t) - 1] = type & 3;

	// Time
	if (ts < AEM_TS_BEGIN) ts = (uint64_t)time(NULL);
	ts -= AEM_TS_BEGIN;
	const uint32_t ts32 = (ts > UINT32_MAX) ? 1 : ts;
	memcpy(msg + AEM_MSG_HDR_SZ - sizeof(uint32_t), (const unsigned char * const)&ts32, sizeof(uint32_t));
}
