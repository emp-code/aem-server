#ifndef AEM_EMAIL_H
#define AEM_EMAIL_H

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

enum dkim_algo {
	AEM_DKIM_RSA_BAD_SHA1, // Bad: Revoked (empty key), missing, or invalid
	AEM_DKIM_RSA_512_SHA1,
	AEM_DKIM_RSA_1024_SHA1,
	AEM_DKIM_RSA_2048_SHA1,

	AEM_DKIM_RSA_BAD_SHA256,
	AEM_DKIM_RSA_512_SHA256,
	AEM_DKIM_RSA_1024_SHA256,
	AEM_DKIM_RSA_2048_SHA256,
	AEM_DKIM_RSA_4096_SHA256,

	AEM_DKIM_ED25519_BAD_SHA256,
	AEM_DKIM_ED25519_SHA256,

	// Available for future use
	AEM_DKIM_UNUSED_1,
	AEM_DKIM_UNUSED_2,
	AEM_DKIM_UNUSED_3,
	AEM_DKIM_UNUSED_4,
	AEM_DKIM_UNUSED_5
};

#define AEM_DKIM_INFOBYTES 12

#define AEM_DKIM_IDENTITY_NO 0
#define AEM_DKIM_IDENTITY_EF 1
#define AEM_DKIM_IDENTITY_HF 2
#define AEM_DKIM_IDENTITY_RT 3

#define AEM_DKIM_TEXT_MAXLEN 127 // 7 bits: 0-127

#define AEM_DKIM_SIGTS_MAX 4194303 // ~48.5 days
#define AEM_DKIM_EXPTS_MAX 33554430 // ~388 days

#define AEM_DKIM_HASH_INVALID 0
#define AEM_DKIM_HASH_FAIL 1
#define AEM_DKIM_HASH_PASS_RELAX 2
#define AEM_DKIM_HASH_PASS_SIMPLE 3

struct dkimInfo {
	// Bytes 0-5: Time
	uint64_t ts_sig: 22; // emailInfo.timestamp - t; max=Invalid/Error/Future
	uint64_t ts_exp: 25; // x - ts_sig
	uint64_t reserved: 1;

	// Byte 6
	uint64_t validSig: 1;
	uint64_t headHash: 2;
	uint64_t bodyHash: 2;
	uint64_t addrReject: 1;
	uint64_t hashReject: 1;
	uint64_t sigReject: 1;

	// Byte 7
	uint64_t algo: 4;
	uint64_t dnsFlag_s: 1;
	uint64_t dnsFlag_y: 1;
	uint64_t idValue: 2;

	// Byte 8: Were the headers reformatted by AEM signed?
	uint32_t sgnCt: 1;
	uint32_t sgnDate: 1;
	uint32_t sgnFrom: 1;
	uint32_t sgnId: 1;
	uint32_t sgnMv: 1;
	uint32_t sgnRt: 1;
	uint32_t sgnSubj: 1;
	uint32_t sgnTo: 1;

	// Byte 9
	uint32_t lenDomain: 7;
	uint32_t bodyTruncated: 1;

	// Byte 10
	uint32_t lenSelector: 7;
	uint32_t zUsed: 1;

	// Byte 11
	uint32_t lenNotes: 7;
	uint32_t notEmail: 1;

	// Text fields
	char domain[AEM_DKIM_TEXT_MAXLEN];
	char selector[AEM_DKIM_TEXT_MAXLEN];
	char notes[AEM_DKIM_TEXT_MAXLEN];

	// Temporary, not stored in message
	size_t lenIdentity;
	char identity[AEM_DKIM_TEXT_MAXLEN];
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
