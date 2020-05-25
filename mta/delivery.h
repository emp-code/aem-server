#ifndef AEM_DELIVERY_H
#define AEM_DELIVERY_H

#include "../Global.h"

struct emailInfo {
	unsigned char toAddr32[15];
	unsigned char countryCode[2];
	uint32_t timestamp;
	uint32_t ip;
	int tls_ciphersuite;
	uint8_t tls_version;
	uint8_t attachments;

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
};

void setAccessKey_account(const unsigned char * const newKey);
void setAccessKey_storage(const unsigned char * const newKey);
void setSignKey(const unsigned char * const seed);
void setAccountPid(const pid_t pid);
void setStoragePid(const pid_t pid);

void deliverMessage(char * const to, const size_t lenToTotal, const unsigned char * const msgBody, const size_t lenMsgBody, struct emailInfo email);

#endif
