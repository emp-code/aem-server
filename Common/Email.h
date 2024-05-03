#ifndef AEM_EMAIL_H
#define AEM_EMAIL_H

#include <stdbool.h>
#include <stdint.h>

#include <sodium.h>

#include "../Global.h"

#define AEM_EMAIL_CERT_NAME_HDRFR 96
#define AEM_EMAIL_CERT_NAME_ENVFR 64
#define AEM_EMAIL_CERT_NAME_GREET 32
#define AEM_EMAIL_CERT_NAME_OTHER  0

#define AEM_EMAIL_CERT_TYPE_EDDSA 28
#define AEM_EMAIL_CERT_TYPE_EC521 24
#define AEM_EMAIL_CERT_TYPE_EC384 20
#define AEM_EMAIL_CERT_TYPE_EC256 16
#define AEM_EMAIL_CERT_TYPE_RSA4K 12
#define AEM_EMAIL_CERT_TYPE_RSA2K  8
#define AEM_EMAIL_CERT_TYPE_RSA1K  4
#define AEM_EMAIL_CERT_TYPE_NONE   0

struct dkimInfo {
	bool algoRsa;
	bool algoSha256;
	bool dnsFlag_s;
	bool dnsFlag_y;
	bool headSimple;
	bool bodySimple;
	bool fullId;
	bool bodyTrunc;

	bool sgnAll;
	bool sgnDate;
	bool sgnFrom;
	bool sgnMsgId;
	bool sgnReplyTo;
	bool sgnSubject;
	bool sgnTo;

	uint32_t ts_expr;
	uint32_t ts_sign;

	size_t lenDomain; // 0-63 -> 4-67
	char domain[67];
};

struct emailInfo {
	unsigned char ccBytes[2];
	uint32_t timestamp;
	uint32_t ip;
	uint8_t attachCount; // 0..AEM_MAXNUM_ATTACHMENTS

	// SMTP protocol info
	bool protocolEsmtp;
	bool protocolViolation;
	bool invalidCommands;
	bool rareCommands; // NOOP/RSET/etc

	// DNS/Host
	bool ipBlacklisted;
	bool ipMatchGreeting;
	bool dnssec;
	bool dane;

	// TLS info
	uint16_t tls_ciphersuite;
	uint8_t tlsInfo;

	// The five short-text fields
	uint8_t lenEnvTo;
	uint8_t lenHdrTo;
	uint8_t lenGreet;
	uint8_t lenRvDns;
	uint8_t lenAuSys;

	unsigned char envTo[63];
	unsigned char hdrTo[63];
	unsigned char greet[63];
	unsigned char rvDns[63];
	unsigned char auSys[63];

	// The five long-text fields
	uint8_t lenEnvFr; // MAIL FROM
	uint8_t lenHdrFr; // From
	uint8_t lenHdrRt; // Reply-To
	uint8_t lenMsgId; // Message-ID
	uint8_t lenSbjct; // Subject

	unsigned char envFr[255];
	unsigned char hdrFr[255];
	unsigned char hdrRt[255];
	unsigned char msgId[255];
	unsigned char sbjct[255];

	// Header time info
	unsigned char hdrTz;
	uint16_t hdrTs;

	// DKIM
	bool dkimFailed;
	uint8_t dkimCount;
	struct dkimInfo dkim[7];

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

struct emailMeta {
	char to[AEM_SMTP_MAX_TO][64];
	uint16_t toUid[AEM_SMTP_MAX_TO];
	uint8_t toFlags[AEM_SMTP_MAX_TO];
	int toCount;
};

#endif
