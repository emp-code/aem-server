#ifndef AEM_SENDMAIL_H
#define AEM_SENDMAIL_H

#include <stddef.h>
#include <stdint.h>

#define AEM_SENDMAIL_ERR_RECV_GREET -100
#define AEM_SENDMAIL_ERR_SEND_EHLO -101
#define AEM_SENDMAIL_ERR_RECV_EHLO -102
#define AEM_SENDMAIL_ERR_SEND_MAIL -103
#define AEM_SENDMAIL_ERR_RECV_MAIL -104
#define AEM_SENDMAIL_ERR_SEND_RCPT -105
#define AEM_SENDMAIL_ERR_RECV_RCPT -106
#define AEM_SENDMAIL_ERR_SEND_DATA -107
#define AEM_SENDMAIL_ERR_RECV_DATA -108
#define AEM_SENDMAIL_ERR_SEND_BODY -109
#define AEM_SENDMAIL_ERR_RECV_BODY -110
#define AEM_SENDMAIL_ERR_SEND_QUIT -111
#define AEM_SENDMAIL_ERR_RECV_QUIT -112
#define AEM_SENDMAIL_ERR_SEND_STARTTLS -120
#define AEM_SENDMAIL_ERR_RECV_STARTTLS -121

void setDkimAdm(const unsigned char * const seed);
void setDkimUsr(const unsigned char * const seed);

int tlsSetup_sendmail(const unsigned char * const crtData, const size_t crtLen, const unsigned char * const keyData, const size_t keyLen);
void tlsFree_sendmail(void);

int sendMail(const uint32_t ip, const int userLevel, const unsigned char *replyId, const size_t lenReplyId, const unsigned char * const addrFrom, const size_t lenAddrFrom, const unsigned char * const addrTo, const size_t lenAddrTo, const unsigned char * const title, const size_t lenTitle, const unsigned char * const body, const size_t lenBody);

#endif
