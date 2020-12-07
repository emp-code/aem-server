#ifndef AEM_EMAIL_H
#define AEM_EMAIL_H

#include <stdbool.h>
#include <stdint.h>

#include "../Global.h"

struct emailInfo {
	unsigned char ccBytes[2];
	uint32_t timestamp;
	uint32_t ip;
	uint16_t tls_ciphersuite;
	uint8_t tls_version;
	uint8_t attachCount; // 0..AEM_MAXNUM_ATTACHMENTS

	// SMTP protocol info
	bool protocolEsmtp;
	bool protocolViolation;
	bool quitReceived;
	bool invalidCommands;
	bool rareCommands; // NOOP/RSET/etc
	bool toMultiple;

	// DNS/Host info
	bool ipBlacklisted;
	bool greetingIpMatch;
	bool dnssec;
	bool dane;

	// Client Cert
	unsigned char certInfo;
	unsigned char certKeysize;

	// The four under-128 fields
	uint8_t lenEnvTo;
	uint8_t lenHeaderTo;
	uint8_t lenGreeting;
	uint8_t lenRdns;

	unsigned char envTo[31];
	unsigned char headerTo[31];
	unsigned char greeting[127];
	unsigned char rdns[127];

	// The four under-256 fields
	uint8_t lenEnvFrom;
	uint8_t lenHeaderFrom;
	uint8_t lenMsgId;
	uint8_t lenSubject;

	unsigned char envFrom[255];
	unsigned char headerFrom[255];
	unsigned char msgId[255];
	unsigned char subject[255];

	// Attachments
	unsigned char *attachment[AEM_MAXNUM_ATTACHMENTS];
	size_t lenAttachment[AEM_MAXNUM_ATTACHMENTS];

	// Header time info
	unsigned char headerTz;
	uint16_t headerTs;

	// DKIM
	uint8_t dkimCount;
	unsigned char dkimInfo[15][4];

	// 2-bit data fields
	uint8_t caa;
	uint8_t dmarc;
	uint8_t spf;
};

#endif
