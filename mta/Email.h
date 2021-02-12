#ifndef AEM_EMAIL_H
#define AEM_EMAIL_H

#include <stdbool.h>
#include <stdint.h>

#include "../Global.h"

#define AEM_EMAIL_CERT_EDDSA 57344
#define AEM_EMAIL_CERT_EC521 49152
#define AEM_EMAIL_CERT_EC384 40960
#define AEM_EMAIL_CERT_EC256 32768
#define AEM_EMAIL_CERT_RSA4K 24576
#define AEM_EMAIL_CERT_RSA2K 16384
#define AEM_EMAIL_CERT_RSA1K  8192
#define AEM_EMAIL_CERT_NONE      0

#define AEM_EMAIL_CERT_MATCH_ENVFROM    64
#define AEM_EMAIL_CERT_MATCH_HEADERFROM 32
#define AEM_EMAIL_CERT_MATCH_GREETING   16
#define AEM_EMAIL_CERT_MATCH_RDNS        8

struct emailInfo {
	unsigned char ccBytes[2];
	uint32_t timestamp;
	uint32_t ip;
	uint8_t attachCount; // 0..AEM_MAXNUM_ATTACHMENTS

	// SMTP protocol info
	bool protocolEsmtp;
	bool protocolViolation;
	bool quitReceived;
	bool invalidCommands;
	bool rareCommands; // NOOP/RSET/etc
	bool toMultiple;

	// DNS/Host
	bool ipBlacklisted;
	bool greetingIpMatch;
	bool dnssec;
	bool dane;

	// TLS info
	uint16_t tlsInfo;
	uint16_t tls_ciphersuite;

	// The four short text fields
	uint8_t lenEnvTo;
	uint8_t lenHeaderTo;
	uint8_t lenGreeting;
	uint8_t lenRdns;

	unsigned char envTo[31];
	unsigned char headerTo[63];
	unsigned char greeting[127];
	unsigned char rdns[127];

	// The four long text fields
	uint8_t lenEnvFrom;
	uint8_t lenHeaderFrom;
	uint8_t lenMsgId;
	uint8_t lenSubject;

	unsigned char envFrom[255];
	unsigned char headerFrom[255];
	unsigned char msgId[255];
	unsigned char subject[255];

	// Header time info
	unsigned char headerTz;
	uint16_t headerTs;

	// DKIM
	uint8_t dkimCount;
	unsigned char dkimInfo[15][4];

	// 2-bit data fields
	uint8_t dmarc;
	uint8_t spf;

	// Headers, Body, Attachments
	unsigned char *head;
	size_t lenHead;

	unsigned char *body;
	size_t lenBody;

	unsigned char *attachment[AEM_MAXNUM_ATTACHMENTS];
	size_t lenAttachment[AEM_MAXNUM_ATTACHMENTS];
};

#endif
