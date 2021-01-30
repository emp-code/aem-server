#ifndef AEM_API_SENDMAIL_H
#define AEM_API_SENDMAIL_H

#include <stddef.h>
#include <stdint.h>

enum aem_sendmail_errors {
	AEM_SENDMAIL_ERR_SEND_EHLO, AEM_SENDMAIL_ERR_RECV_EHLO,
	AEM_SENDMAIL_ERR_SEND_MAIL, AEM_SENDMAIL_ERR_RECV_MAIL,
	AEM_SENDMAIL_ERR_SEND_RCPT, AEM_SENDMAIL_ERR_RECV_RCPT,
	AEM_SENDMAIL_ERR_SEND_DATA, AEM_SENDMAIL_ERR_RECV_DATA,
	AEM_SENDMAIL_ERR_SEND_BODY, AEM_SENDMAIL_ERR_RECV_BODY,
	AEM_SENDMAIL_ERR_SEND_QUIT, AEM_SENDMAIL_ERR_RECV_QUIT,
	AEM_SENDMAIL_ERR_SEND_STLS, AEM_SENDMAIL_ERR_RECV_STLS,

	AEM_SENDMAIL_ERR_RECV_GREET,
	AEM_SENDMAIL_ERR_NOTLS,
	AEM_SENDMAIL_ERR_MISC
};

struct outEmail {
	uint32_t ip;
	char mxDomain[256];
	char replyId[256];
	char addrFrom[256];
	char addrTo[256];
	char subject[256];
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

void setDkimAdm(const unsigned char * const seed);
void setDkimUsr(const unsigned char * const seed);
void setMsgIdKeys(const unsigned char * const src);
void sm_clearKeys(void);

int tlsSetup_sendmail(void);
void tlsFree_sendmail(void);

unsigned char sendMail(const unsigned char * const upk, const int userLevel, const struct outEmail * const email, struct outInfo * const info);

#endif
