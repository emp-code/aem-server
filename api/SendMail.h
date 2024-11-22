#ifndef AEM_API_SENDMAIL_H
#define AEM_API_SENDMAIL_H

#include <stddef.h>
#include <stdint.h>

struct outEmail {
	char mxDomain[128];
	char addrFrom[25];
	char addrTo[128];
	char replyId[128];
	char subject[128];
	unsigned char rsaKey[2048];

	uint16_t uid;
	bool isAdmin;

	uint32_t ip;
	unsigned char cc[2];
	unsigned char fromAddr32[10];

	size_t lenRsaKey;

	size_t lenBody;
	char *body;
};

struct outInfo {
	uint32_t timestamp;
	int tls_ciphersuite;
	int tls_version;
	int lenGreeting;
	int lenStatus;
	char greeting[127];
	char status[127];
};

int sendMail_tls_init(const unsigned char * const crt, const size_t lenCrt, const unsigned char * const key, const size_t lenKey, const unsigned char * const domain, const size_t lenDomain);
void sendMail_tls_free(void);

unsigned char sendMail(const struct outEmail * const email, struct outInfo * const info);

#endif
