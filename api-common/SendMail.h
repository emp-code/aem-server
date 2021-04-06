#ifndef AEM_API_SENDMAIL_H
#define AEM_API_SENDMAIL_H

#include <stddef.h>
#include <stdint.h>

struct outEmail {
	uint32_t ip;
	char mxDomain[256];
	char replyId[256];
	char addrFrom[256];
	char addrTo[256];
	char subject[256];

	size_t lenBody;
	char *body;
};

struct outInfo {
	uint32_t timestamp;
	int tls_ciphersuite;
	uint8_t tls_version;
	uint8_t tls_info;
	char greeting[257];
	char info[257];
};

void sm_clearKeys(void);

int tlsSetup_sendmail(void);
void tlsFree_sendmail(void);

unsigned char sendMail(const unsigned char * const upk, const int userLevel, const struct outEmail * const email, struct outInfo * const info);

#endif
