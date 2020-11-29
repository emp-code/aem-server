#ifndef AEM_EMAIL_H
#define AEM_EMAIL_H

#include <stdbool.h>
#include <stdint.h>

#include "../Global.h"

struct emailInfo {
	unsigned char toAddr32[10];
	unsigned char ccBytes[2];
	uint32_t timestamp;
	uint32_t ip;
	int tls_ciphersuite;
	uint8_t tls_version;
	uint8_t attachCount; // 0..AEM_MAXNUM_ATTACHMENTS

	bool protocolEsmtp;
	bool protocolViolation;
	bool quitReceived;
	bool invalidCommands;
	bool rareCommands; // NOOP/RSET/etc
	bool isShield;

	uint8_t lenGreeting;
	uint8_t lenRdns;
	uint8_t lenCharset;
	uint8_t lenEnvFrom;

	unsigned char greeting[127];
	unsigned char rdns[127];
	unsigned char charset[127];
	unsigned char envFrom[127];

	unsigned char *attachment[AEM_MAXNUM_ATTACHMENTS];
	size_t attachSize[AEM_MAXNUM_ATTACHMENTS];
};

#endif
