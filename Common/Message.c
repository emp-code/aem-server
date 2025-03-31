#include <strings.h>
#include <string.h>

#include "binTs.h"
#include "../Global.h"

#include "Message.h"

void aem_msg_init(unsigned char * const msg, const int type, uint64_t binTs) {
	bzero(msg, AEM_MSG_HDR_SZ);

	if (binTs == 0) binTs = getBinTs();
	msg[AEM_MSG_HDR_SZ - 6] = ((type & 3) << 4) | ((binTs & 3) << 6);
	msg[AEM_MSG_HDR_SZ - 5] = (binTs & 0x03FC) >> 2;
	msg[AEM_MSG_HDR_SZ - 4] = (binTs & 0x03FC00) >> 10;
	msg[AEM_MSG_HDR_SZ - 3] = (binTs & 0x03FC0000) >> 18;
	msg[AEM_MSG_HDR_SZ - 2] = (binTs & 0x03FC000000) >> 26;
	msg[AEM_MSG_HDR_SZ - 1] = (binTs & 0x03FC00000000) >> 34;
}
