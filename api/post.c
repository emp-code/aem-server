#include <ctype.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>

#ifdef AEM_TLS
#include "ClientTLS.h"
#else
#include <sys/socket.h>
#endif

#include <sodium.h>

#include "../Global.h"
#include "../Common/Addr32.h"
#include "../Common/Message.h"
#include "../Common/ValidUtf8.h"
#include "../Common/api_req.h"
#include "../Common/memeq.h"
#include "../IntCom/Client.h"

#include "Error.h"
#include "Respond.h"
#include "SendMail.h"

#include "post.h"

static unsigned char ourDomain[AEM_MAXLEN_OURDOMAIN];

void setOurDomain(const unsigned char * dom, const size_t len) {
	bzero(ourDomain, AEM_MAXLEN_OURDOMAIN);
	memcpy(ourDomain, dom, len);
}

static void message_browse(const uint16_t uid, const int flags, const unsigned char urlData[AEM_API_REQ_DATA_LEN], const unsigned char * const accData, const size_t lenAccData) {
	const bool haveMsgId = !sodium_is_zero(urlData, AEM_API_REQ_DATA_LEN);

	unsigned char stoParam[sizeof(uint16_t) * 2];
	memcpy(stoParam, (const unsigned char * const)&uid, sizeof(uint16_t));
	if (haveMsgId) memcpy(stoParam + sizeof(uint16_t), urlData, sizeof(uint16_t));

	unsigned char *stoData = NULL;
	const int stoRet = intcom(AEM_INTCOM_SERVER_STO, (flags & AEM_API_MESSAGE_BROWSE_FLAG_OLDER) ? AEM_INTCOM_OP_BROWSE_OLD : AEM_INTCOM_OP_BROWSE_NEW, stoParam, sizeof(uint16_t) * (haveMsgId? 2 : 1), &stoData, 0);

	if (stoRet == AEM_INTCOM_RESPONSE_NOTEXIST) {
		const unsigned char rb = AEM_API_ERR_MESSAGE_BROWSE_NOTFOUND;
		apiResponse(&rb, 1);
		return;
	}

	if (stoRet == AEM_INTCOM_RESPONSE_OK) {
		const unsigned char rb = AEM_API_ERR_MESSAGE_BROWSE_NOMORE;
		apiResponse(&rb, 1);
		return;
	}

	if (stoRet < 8 || stoRet > AEM_EVP_MAXSIZE) {
		if (stoData != NULL) free(stoData);
		syslog(LOG_INFO, "Invalid response from Storage: %d", stoRet);
		const unsigned char rb = AEM_API_ERR_INTERNAL;
		apiResponse(&rb, 1);
		return;
	}

	unsigned char *response;
	size_t lenResponse = stoRet;

	if (lenAccData > 0) {
		lenResponse += lenAccData + AEM_MAXLEN_OURDOMAIN;
		response = malloc(lenResponse);
		if (response == NULL) {
			syslog(LOG_INFO, "Failed allocation");
			const unsigned char rb = AEM_API_ERR_INTERNAL;
			apiResponse(&rb, 1);
			return;
		}

		memcpy(response, accData, lenAccData);
		memcpy(response + lenAccData, ourDomain, AEM_MAXLEN_OURDOMAIN);
		memcpy(response + lenAccData + AEM_MAXLEN_OURDOMAIN, stoData, stoRet);
		free(stoData);
	} else {
		response = stoData;
	}

	apiResponse(response, lenResponse);
	free(response);
}

static const unsigned char *cpyEmail(const unsigned char * const src, const size_t lenSrc, char * const out, const size_t min) {
	out[0] = '\0';

	const unsigned char * const lf = memchr(src, '\n', lenSrc);
	if (lf == NULL) return NULL;

	size_t len = lf - src;
	if (len < min || len > 127) return NULL;

	for (size_t i = 0; i < len; i++) {
		if (src[i] < 32 || src[i] >= 127) return NULL;
		out[i] = src[i];
	}

	out[len] = '\0';
	return src + len + 1;
}

static unsigned char send_email(const uint16_t uid, const bool isAdmin, const unsigned char * const rsaKey, const size_t lenRsaKey, const unsigned char urlData[AEM_API_REQ_DATA_LEN], const unsigned char * const src, const size_t lenSrc) {
	struct outEmail email;
	bzero(&email, sizeof(email));

	email.uid = uid;
	email.isAdmin = isAdmin;
	email.lenRsaKey = lenRsaKey;
	memcpy(email.rsaKey, rsaKey, lenRsaKey);

	// 'From' address verified by AEM-Account
	memcpy(email.addrFrom, urlData, AEM_API_REQ_DATA_LEN);
	email.addrFrom[AEM_API_REQ_DATA_LEN] = '\0';
	addr32_store(email.fromAddr32, (const unsigned char*)email.addrFrom, 24);

	// Data from POST body
	const unsigned char *p = src;
	const unsigned char * const end = src + lenSrc;
	p = cpyEmail(p, end - p, email.addrTo,  5); if (p == NULL) return AEM_API_ERR_MESSAGE_CREATE_EXT_HDR_ADTO;
	p = cpyEmail(p, end - p, email.replyId, 0); if (p == NULL) return AEM_API_ERR_MESSAGE_CREATE_EXT_HDR_RPLY;
	p = cpyEmail(p, end - p, email.subject, 2); if (p == NULL) return AEM_API_ERR_MESSAGE_CREATE_EXT_HDR_SUBJ;

	if (strspn(email.replyId, "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz$%+-.=@_") != strlen(email.replyId)) return AEM_API_ERR_MESSAGE_CREATE_EXT_HDR_RPLY;

	// Body
	const size_t lenBody = end - p;
	if (lenBody < 5 || lenBody > 99999) return AEM_API_ERR_MESSAGE_CREATE_EXT_BDY_SIZE;
	if (!isValidUtf8((const unsigned char*)p, lenBody)) return AEM_API_ERR_MESSAGE_CREATE_EXT_BDY_UTF8;

	email.body = malloc(lenBody + 1000);
	if (email.body == NULL) {syslog(LOG_ERR, "Failed malloc"); return AEM_API_ERR_INTERNAL;}

	email.lenBody = 0;
	size_t lineLength = 0;
	for (size_t copied = 0; copied < lenBody; copied++) {
		if (p[copied] == '\n') { // Linebreak
			memcpy(email.body + email.lenBody, "\r\n", 2);
			email.lenBody += 2;
			lineLength = 0;
		} else if ((p[copied] < 32 && p[copied] != '\t') || p[copied] == 127) { // Control characters
			free(email.body);
			return AEM_API_ERR_MESSAGE_CREATE_EXT_BDY_CTRL;
		} else if (p[copied] > 127) { // UTF-8
			// TODO - Forbid for now
			free(email.body);
			return AEM_API_ERR_INTERNAL;
		} else { // ASCII
			lineLength++;
			if (lineLength > 998) {
				free(email.body);
				return AEM_API_ERR_MESSAGE_CREATE_EXT_BDY_LONG;
			}

			email.body[email.lenBody] = p[copied];
			email.lenBody++;
		}

		if (email.lenBody > lenBody + 950) {
			free(email.body);
			return AEM_API_ERR_MESSAGE_CREATE_EXT_BDY_SIZE;
		}
	}

	while (email.lenBody > 0 && isspace(email.body[email.lenBody - 1]))
		email.lenBody--;

	memcpy(email.body + email.lenBody, "\r\n", 2);
	email.lenBody += 2;

	if (email.lenBody < 15) {
		free(email.body);
		return AEM_API_ERR_MESSAGE_CREATE_EXT_BDY_SIZE;
	}

	// Domain
	const char * const emailDomain = strchr(email.addrTo + 1, '@');
	if (emailDomain == NULL || strlen(emailDomain) < 5) { // 5=@a.bc
		free(email.body);
		return AEM_API_ERR_MESSAGE_CREATE_EXT_HDR_ADTO;
	}

	unsigned char *enq = NULL;
	const int32_t lenEnq = intcom(AEM_INTCOM_SERVER_ENQ, AEM_ENQUIRY_MX, (const unsigned char*)emailDomain + 1, strlen(emailDomain) - 1, &enq, 0);
	if (lenEnq < 1 || enq == NULL) {free(email.body); syslog(LOG_ERR, "Failed contacting Enquiry"); return AEM_API_ERR_INTERNAL;}
	if (lenEnq < 12) {free(email.body); free(enq); syslog(LOG_ERR, "Invalid response from Enquiry (1)"); return AEM_API_ERR_INTERNAL;}

	email.ip = *(uint32_t*)enq;
	email.cc = *(uint16_t*)(enq + 4);
	memcpy((unsigned char*)&email, enq + 6, lenEnq - 6);
	free(enq);

	// Send
	struct outInfo info;
	bzero(&info, sizeof(info));
	info.timestamp = (uint32_t)time(NULL);
	const unsigned char ret = sendMail(&email, &info);

	// Delivery Report
	const size_t lenMx = strlen(email.mxDomain);
	const size_t lenAs = strlen(email.asn);
	const size_t lenRd = strlen(email.rdns);
	const size_t lenSb = strlen(email.subject);
	const size_t lenFr = strlen(email.addrFrom);
	const size_t lenTo = strlen(email.addrTo);

	size_t lenDr = AEM_MSG_HDR_SZ + 17 + lenFr + lenTo + lenMx + lenAs + lenRd + info.lenGreeting + info.lenStatus + lenSb + email.lenBody;
	unsigned char dr[lenDr];

	aem_msg_init(dr, AEM_MSG_TYPE_OUT, 0);
	dr[AEM_MSG_HDR_SZ] = lenSb;
	memcpy(dr + AEM_MSG_HDR_SZ + 1, &email.ip, 4);

	// TODO TLS ciphersuite: 2 bytes
	dr[AEM_MSG_HDR_SZ + 5] = 0;
	dr[AEM_MSG_HDR_SZ + 6] = 0;

	/* IB 0 */ dr[AEM_MSG_HDR_SZ + 7] = 0; // TODO: TLS Version + Attachments
	/* IB 1 */ dr[AEM_MSG_HDR_SZ + 8] = email.cc & 31;
	/* IB 2 */ dr[AEM_MSG_HDR_SZ + 9] = (email.cc >> 8) & 31;
	/* IB 3 */ dr[AEM_MSG_HDR_SZ + 10] = lenFr;
	/* IB 4 */ dr[AEM_MSG_HDR_SZ + 11] = lenTo;
	/* IB 5 */ dr[AEM_MSG_HDR_SZ + 12] = lenMx;
	/* IB 6 */ dr[AEM_MSG_HDR_SZ + 13] = lenAs;
	/* IB 7 */ dr[AEM_MSG_HDR_SZ + 14] = lenRd;
	/* IB 8 */ dr[AEM_MSG_HDR_SZ + 15] = info.lenGreeting;
	/* IB 9 */ dr[AEM_MSG_HDR_SZ + 16] = info.lenStatus;

	int off = AEM_MSG_HDR_SZ + 17;
	memcpy(dr + off, email.addrFrom, lenFr);           off += lenFr;
	memcpy(dr + off, email.addrTo, lenTo);             off += lenTo;
	memcpy(dr + off, email.mxDomain, lenMx);           off += lenMx;
	memcpy(dr + off, email.asn, lenAs);                off += lenAs;
	memcpy(dr + off, email.rdns, lenRd);               off += lenRd;
	memcpy(dr + off, info.greeting, info.lenGreeting); off += info.lenGreeting;
	memcpy(dr + off, info.status, info.lenStatus);     off += info.lenStatus;
	memcpy(dr + off, email.subject, lenSb);            off += lenSb;
	memcpy(dr + off, email.body, email.lenBody);       off += email.lenBody;
	free(email.body);

	const int32_t icRet = intcom(AEM_INTCOM_SERVER_STO, uid, dr, lenDr, NULL, 0);
	return (icRet == AEM_INTCOM_RESPONSE_ERR) ? AEM_API_ERR_INTERNAL : AEM_API_STATUS_OK;
}

static unsigned char send_imail(const uint16_t uid, const unsigned char urlData[AEM_API_REQ_DATA_LEN], const unsigned char * const src, const size_t lenSrc, const bool e2ee) {
	size_t lenMsg = AEM_MSG_HDR_SZ + 23 + lenSrc;
	unsigned char msg[lenMsg];
	aem_msg_init(msg, AEM_MSG_TYPE_INT, 0);

	msg[AEM_MSG_HDR_SZ] = e2ee ? 64 : 0; // IntMsg InfoByte
	memset(msg + AEM_MSG_HDR_SZ + 1, 0xFF, 2); // TODO
	memcpy(msg + AEM_MSG_HDR_SZ + 3, urlData, 20); // From/To Addr32
	memcpy(msg + AEM_MSG_HDR_SZ + 23, src, lenSrc);

	const int32_t icRet = intcom(AEM_INTCOM_SERVER_STO, uid, msg, lenMsg, NULL, 0);
	return (icRet == AEM_INTCOM_RESPONSE_ERR) ? AEM_API_ERR_INTERNAL : AEM_API_STATUS_OK;
}

static unsigned char send_pmail(const uint16_t * const uid, const unsigned int count, const unsigned char urlData[AEM_API_REQ_DATA_LEN], const unsigned char * const src, const size_t lenSrc) {
	size_t lenMsg = AEM_MSG_HDR_SZ + 11 + lenSrc;
	unsigned char msg[lenMsg];
	aem_msg_init(msg, AEM_MSG_TYPE_INT, 0);

	msg[AEM_MSG_HDR_SZ] = 128; // IntMsg InfoByte: Public
	memcpy(msg + AEM_MSG_HDR_SZ + 1, urlData, 10); // From Addr32
	memcpy(msg + AEM_MSG_HDR_SZ + 11, src, lenSrc);

	bool ok = true;
	for (unsigned int i = 0; i < count; i++) {
		if (intcom(AEM_INTCOM_SERVER_STO, uid[i], msg, lenMsg, NULL, 0) == AEM_INTCOM_RESPONSE_ERR) ok = false;
	}

	return ok? AEM_API_STATUS_OK : AEM_API_ERR_INTERNAL;
}

static unsigned char message_create(const int flags, const unsigned char * const cuid, const size_t lenCuid, const unsigned char urlData[AEM_API_REQ_DATA_LEN], const unsigned char * const src, const size_t lenSrc) {
	if (lenCuid < 1) return AEM_API_ERR_INTERNAL;
	if (lenCuid == 1) return cuid[0];

	const uint16_t uid = *(const uint16_t*)cuid & 4095;
	if ((flags & AEM_API_MESSAGE_CREATE_FLAG_EMAIL) != 0 && lenCuid > 2) {
		return send_email(uid, (cuid[1] & 128) != 0, cuid + 2, lenCuid - 2, urlData, src, lenSrc);
	} else if ((flags & AEM_API_MESSAGE_CREATE_FLAG_PUB) != 0) {
		return send_pmail((const uint16_t * const)cuid, lenCuid / 2, urlData, src, lenSrc);
	} else if (lenCuid == 2) {
		return send_imail(uid, urlData, src, lenSrc, (flags == AEM_API_MESSAGE_CREATE_FLAG_E2EE));
	}

	return AEM_API_ERR_INTERNAL;
}

static unsigned char message_delete(const uint16_t uid, const unsigned char urlData[AEM_API_REQ_DATA_LEN], const int flags) {
	const int32_t icRet = intcom(AEM_INTCOM_SERVER_STO, AEM_USERCOUNT + uid, urlData, (flags == AEM_API_MESSAGE_DELETE_FLAG_EMPTY) ? 1 : 2, NULL, 0);
	if (icRet == AEM_INTCOM_RESPONSE_NOTEXIST) return AEM_API_ERR_MESSAGE_DELETE_NOTFOUND;
	return (icRet == AEM_INTCOM_RESPONSE_OK) ? AEM_API_STATUS_OK : AEM_API_ERR_INTERNAL;
}

static unsigned char message_upload(const uint16_t uid, const unsigned char urlData[AEM_API_REQ_DATA_LEN], const unsigned char * const src, const size_t lenSrc) {
	size_t lenMsg = AEM_MSG_HDR_SZ + AEM_API_REQ_DATA_LEN + lenSrc;
	unsigned char msg[lenMsg];
	aem_msg_init(msg, AEM_MSG_TYPE_UPL, 0);

	msg[AEM_MSG_HDR_SZ] = urlData[0] & 127; // lenFileName
	memcpy(msg + AEM_MSG_HDR_SZ + 1, urlData + 1, AEM_API_REQ_DATA_LEN - 1);
	memcpy(msg + AEM_MSG_HDR_SZ + AEM_API_REQ_DATA_LEN, src, lenSrc);

	const int32_t icRet = intcom(AEM_INTCOM_SERVER_STO, uid, msg, lenMsg, NULL, 0);
	return (icRet == AEM_INTCOM_RESPONSE_OK) ? AEM_API_STATUS_OK : AEM_API_ERR_INTERNAL;
}

static long readHeaders(void) {
	unsigned char buf[1000];
#ifdef AEM_TLS
	int ret = tls_peek(buf, 1000);
#else
	int ret = recv(AEM_FD_SOCK_CLIENT, buf, 1000, MSG_PEEK);
#endif
	if (ret < 10) return -1;

	unsigned char * const headersEnd = memmem(buf, ret, "\r\n\r\n", 4);
	if (headersEnd == NULL) return -2;
	*headersEnd = '\0';

	const unsigned char *clBegin = memcasemem(buf, headersEnd - buf, "Content-Length:", 15);
	if (clBegin == NULL || headersEnd - clBegin < 10) return 0; // No body
	clBegin += 15;
	if (*clBegin == ' ') clBegin++;

	const long cl = strtol((const char * const)clBegin, NULL, 10);
	if (cl < 10) return -4;

#ifdef AEM_TLS
	tls_recv(buf, (headersEnd + 4) - buf); // Next recv returns the POST body
#else
	recv(AEM_FD_SOCK_CLIENT, buf, (headersEnd + 4) - buf, 0); // Next recv returns the POST body
#endif
	return cl;
}

static void handleContinue(const unsigned char * const req, const size_t lenBody) {
	// Used with Account/Create and Private/Update. Prevents AEM-API from accessing the sensitive request data.
	unsigned char body[AEM_API_REQ_LEN + lenBody];
	if (
#ifdef AEM_TLS
	tls_recv(body + AEM_API_REQ_LEN, lenBody)
#else
	recv(AEM_FD_SOCK_CLIENT, body + AEM_API_REQ_LEN, lenBody, MSG_WAITALL)
#endif
	!= (ssize_t)lenBody) {
		respond404();
		return;
	}
	memcpy(body, req, AEM_API_REQ_LEN);

	// Redo the Account IntCom request, now with the POST body
	unsigned char *icData = NULL;
	const int32_t icRet = intcom(AEM_INTCOM_SERVER_ACC, AEM_INTCOM_OP_POST, body, AEM_API_REQ_LEN + lenBody, &icData, 0);

	if (icRet > AEM_LEN_APIRESP_BASE) {
		setRbk(icData + 3 + AEM_API_REQ_DATA_LEN + AEM_API_BODY_KEYSIZE);
		apiResponse(icData + AEM_LEN_APIRESP_BASE, icRet - AEM_LEN_APIRESP_BASE);
	} else {
		syslog(LOG_INFO, "Continue - invalid response from Account: %d", icRet);
		respond500();
	}

	if (icData != NULL) free(icData);
}

static void handleGet(const int cmd, const int flags, const uint16_t uid, const unsigned char urlData[AEM_API_REQ_DATA_LEN], const unsigned char * const icData, const size_t lenIcData) {
	switch (cmd) {
		case AEM_API_MESSAGE_BROWSE:
			message_browse(uid, flags, urlData, icData, lenIcData);
		break;

		case AEM_API_MESSAGE_DELETE: {
			const unsigned char rb = message_delete(uid, urlData, flags);
			apiResponse(&rb, 1);
		break;}

		// Forward response from AEM-Account
		case AEM_API_ACCOUNT_BROWSE:
		case AEM_API_ACCOUNT_DELETE:
		case AEM_API_ACCOUNT_UPDATE:
		case AEM_API_ADDRESS_CREATE:
		case AEM_API_ADDRESS_DELETE:
		case AEM_API_ADDRESS_UPDATE:
		case AEM_API_SETTING_LIMITS:
			apiResponse(icData, lenIcData);
		break;

		default:
			syslog(LOG_INFO, "Received unknown command from Account (GET): %d", cmd);
			const unsigned char rb = AEM_API_ERR_INTERNAL;
			apiResponse(&rb, 1);
	}
}

static unsigned char handlePost(const int cmd, const int flags, const uint16_t uid, const unsigned char urlData[AEM_API_REQ_DATA_LEN], const unsigned char requestBodyKey[AEM_API_BODY_KEYSIZE], const unsigned char * const icData, const size_t lenIcData, unsigned char * const body, const size_t lenBody) {
	if (
#ifdef AEM_TLS
	tls_recv(body, lenBody)
#else
	recv(AEM_FD_SOCK_CLIENT, body, lenBody, MSG_WAITALL)
#endif
	!= (ssize_t)lenBody)
		return AEM_API_ERR_RECV;

	// Authenticate and decrypt
	unsigned char nonce[crypto_aead_aes256gcm_NPUBBYTES];
	bzero(nonce, crypto_aead_aes256gcm_NPUBBYTES);

	unsigned char decBody[lenBody - crypto_aead_aes256gcm_ABYTES];
	if (crypto_aead_aes256gcm_decrypt(decBody, NULL, NULL, body, lenBody, NULL, 0, nonce, requestBodyKey) != 0)
		return AEM_API_ERR_DECRYPT;

	// Choose action
	switch (cmd) {
		case AEM_API_MESSAGE_CREATE: return message_create(flags, icData, lenIcData, urlData, decBody, lenBody - crypto_aead_aes256gcm_ABYTES);
		case AEM_API_MESSAGE_UPLOAD: return message_upload(uid, urlData, decBody, lenBody - crypto_aead_aes256gcm_ABYTES);
	}

	syslog(LOG_INFO, "Received unknown command from Account (POST): %d", cmd);
	return AEM_API_ERR_INTERNAL;
}

void aem_api_process(unsigned char * const req, const bool isPost) {
	if (labs(((const union aem_req * const)req)->n.binTs - (((long)time(NULL) - AEM_TS_BEGIN) * 1000)) > AEM_API_TIMEDIFF) {respond404(); return;}

	// Forward the request to Account
	unsigned char *icData = NULL;
	int32_t icRet = intcom(AEM_INTCOM_SERVER_ACC, isPost? AEM_INTCOM_OP_POST : AEM_INTCOM_OP_GET, req, AEM_API_REQ_LEN, &icData, 0);

	if (icRet == AEM_INTCOM_RESPONSE_AUTHFAIL) {respond403(); return;}

	if (icRet < AEM_LEN_APIRESP_BASE && (!isPost || icRet != AEM_INTCOM_RESPONSE_CONTINUE)) {
		if (icData != NULL) free(icData);
		syslog(LOG_INFO, "Invalid response from Account: %d", icRet);
		respond500();
		return;
	}

	// The request is authentic
	const long lenBody = isPost? readHeaders() : 0;
	if (isPost && (lenBody < 1 || lenBody > AEM_MSG_W_MAXSIZE)) {
		if (icRet == AEM_INTCOM_RESPONSE_CONTINUE) {
			respond400();
			return;
		}

		setRbk(icData + 3 + AEM_API_REQ_DATA_LEN + AEM_API_BODY_KEYSIZE);
		const unsigned char rb = AEM_API_ERR_POST;
		apiResponse(&rb, 1);
	} else if (icRet == AEM_INTCOM_RESPONSE_CONTINUE) {
		return (isPost && lenBody < 99999) ? handleContinue(req, lenBody) : respond500();
	} else {
		setRbk(icData + 3 + AEM_API_REQ_DATA_LEN + AEM_API_BODY_KEYSIZE);

		if (isPost) {
			unsigned char * const postBody = malloc(lenBody);
			if (postBody == NULL) {
				syslog(LOG_ERR, "Failed malloc");
			} else {
				const unsigned char rb = handlePost(icData[0], icData[1], icData[2], icData + 3, icData + 3 + AEM_API_REQ_DATA_LEN, icData + AEM_LEN_APIRESP_BASE, icRet - AEM_LEN_APIRESP_BASE, postBody, lenBody);
				free(postBody);
				apiResponse(&rb, 1);
			}
		} else {
			handleGet(icData[0], icData[1], icData[2], icData + 3, icData + AEM_LEN_APIRESP_BASE, icRet - AEM_LEN_APIRESP_BASE);
		}
	}

	sodium_memzero(icData, icRet);
	free(icData);
	clrRbk();
}
