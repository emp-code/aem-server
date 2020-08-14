#ifndef AEM_SENDMAIL_H
#define AEM_SENDMAIL_H

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

void setDkimAdm(const unsigned char * const seed);
void setDkimUsr(const unsigned char * const seed);
void setMsgIdKeys(const unsigned char * const src);
void sm_clearKeys();

int tlsSetup_sendmail(const unsigned char * const crtData, const size_t crtLen, const unsigned char * const keyData, const size_t keyLen);
void tlsFree_sendmail(void);

unsigned char sendMail(const uint32_t ip, const unsigned char * const upk, const int userLevel,
	const unsigned char * const replyId,  const size_t lenReplyId,
	const unsigned char * const addrFrom, const size_t lenAddrFrom,
	const unsigned char * const addrTo,   const size_t lenAddrTo,
	const unsigned char * const title,    const size_t lenTitle,
	const unsigned char * const body,     const size_t lenBody
);

#endif
