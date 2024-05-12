#include <ctype.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <syslog.h>
#include <time.h>

#include <sodium.h>

#include "../Global.h"
#include "../Common/Addr32.h"
#include "../Common/Message.h"
#include "../Common/ValidUtf8.h"
#include "../Common/api_req.h"
#include "../Common/memeq.h"
#include "../Common/x509_getCn.h"
#include "../IntCom/Client.h"

#include "Error.h"
#include "Respond.h"
#include "SendMail.h"

#include "post.h"

static unsigned char ourDomain[AEM_MAXLEN_OURDOMAIN];

void setOurDomain(const unsigned char * const crt, const size_t lenCrt) {
	bzero(ourDomain, AEM_MAXLEN_OURDOMAIN);
	size_t lenOurDomain;
	x509_getSubject(ourDomain, &lenOurDomain, crt, lenCrt);
}

static void message_browse(const uint16_t uid, const unsigned char urlData[AEM_API_REQ_DATA_LEN], const unsigned char * const accData, const size_t lenAccData) {
	unsigned char stoParam[19];
	memcpy(stoParam, (const unsigned char * const)&uid, sizeof(uint16_t));
	stoParam[2] = urlData[0] & (AEM_API_MESSAGE_BROWSE_FLAG_OLDER | AEM_API_MESSAGE_BROWSE_FLAG_MSGID);
	if ((urlData[0] & AEM_API_MESSAGE_BROWSE_FLAG_MSGID) != 0) memcpy(stoParam + 3, urlData + 1, 16);

	unsigned char *stoData = NULL;
	const int stoRet = intcom(AEM_INTCOM_SERVER_STO, AEM_INTCOM_OP_BROWSE, stoParam, ((urlData[0] & AEM_API_MESSAGE_BROWSE_FLAG_MSGID) != 0) ? 19 : 3, &stoData, 0);

	if (stoRet < (AEM_ENVELOPE_MINSIZE + 8) || stoRet > (AEM_ENVELOPE_MAXSIZE + 8)) { // +6 (infobytes) +2 (size)
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

static unsigned char send_email(const uint16_t uid, const unsigned char * const rsaKey, const size_t lenRsaKey, const unsigned char urlData[AEM_API_REQ_DATA_LEN], const unsigned char * const src, const size_t lenSrc) {
	struct outEmail email;
	bzero(&email, sizeof(email));

	email.uid = uid;
	email.isAdmin = false; // TODO
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

	unsigned char *mx = NULL;
	const int32_t lenMx = intcom(AEM_INTCOM_SERVER_ENQ, AEM_ENQUIRY_MX, (const unsigned char*)emailDomain + 1, strlen(emailDomain) - 1, &mx, 0);
	if (lenMx < 1 || mx == NULL) {free(email.body); syslog(LOG_ERR, "Failed contacting Enquiry"); return AEM_API_ERR_INTERNAL;}
	if (lenMx < 10) {free(email.body); free(mx); syslog(LOG_ERR, "Invalid response from Enquiry (1)"); return AEM_API_ERR_INTERNAL;}

	const size_t lenMxDomain = lenMx - 6;
	if (lenMxDomain < 4) {free(email.body); free(mx); syslog(LOG_ERR, "Invalid response from Enquiry (2)"); return AEM_API_ERR_INTERNAL;} // a.bc

	memcpy((unsigned char*)(&email.ip), mx, 4);
	memcpy((unsigned char*)(&email.cc), mx + 4, 2);
	memcpy(email.mxDomain, mx + 6, lenMxDomain);
	email.mxDomain[lenMxDomain] = '\0';
	free(mx);

	struct outInfo info;
	bzero(&info, sizeof(info));
	info.timestamp = (uint32_t)time(NULL);

	// Send
	const unsigned char ret = sendMail(&email, &info);

	free(email.body);
	return ret;
}

static unsigned char send_imail(const uint16_t uid, const unsigned char urlData[AEM_API_REQ_DATA_LEN], const unsigned char * const src, const size_t lenSrc) {
	const uint32_t ts = (uint32_t)time(NULL);
	size_t lenMsg = AEM_ENVELOPE_RESERVED_LEN + 58 + lenSrc;
	const size_t padAmount = msg_getPadAmount(lenMsg);
	lenMsg += padAmount;

	unsigned char msg[lenMsg];
	msg[AEM_ENVELOPE_RESERVED_LEN] = padAmount | 16; // 16=IntMsg
	memcpy(msg + AEM_ENVELOPE_RESERVED_LEN + 1, &ts, 4);
	msg[AEM_ENVELOPE_RESERVED_LEN + 5] = 0; // IntMsg InfoByte: 0=Plain; TODO: 0-3: SenderLevel
	memcpy(msg + AEM_ENVELOPE_RESERVED_LEN + 6, urlData, 20); // From/To Addr32
	bzero(msg + AEM_ENVELOPE_RESERVED_LEN + 26, 32); // TODO: APK
	memcpy(msg + AEM_ENVELOPE_RESERVED_LEN + 58, src, lenSrc);

	const int32_t icRet = intcom(AEM_INTCOM_SERVER_STO, uid, msg, lenMsg, NULL, 0);
	return (icRet == AEM_INTCOM_RESPONSE_OK) ? AEM_API_STATUS_OK : AEM_API_ERR_INTERNAL;
}

static unsigned char message_create(const int flags, const unsigned char * const cuid, const size_t lenCuid, const unsigned char urlData[AEM_API_REQ_DATA_LEN], const unsigned char * const src, const size_t lenSrc) {
	if (lenCuid == 0) return AEM_API_ERR_INTERNAL;
	if (lenCuid == 1) return cuid[0];
	const uint16_t uid = *(const uint16_t*)cuid;
	if (uid >= AEM_USERCOUNT) return AEM_API_ERR_INTERNAL;

	if (flags == 0) {
		if (lenCuid != 2) return AEM_API_ERR_INTERNAL;
		return send_imail(uid, urlData, src, lenSrc);
	}

	return send_email(uid, cuid + 2, lenCuid - 2, urlData, src, lenSrc);
}

static unsigned char message_delete(const uint16_t uid, const unsigned char urlData[AEM_API_REQ_DATA_LEN]) {
	const int32_t icRet = intcom(AEM_INTCOM_SERVER_STO, AEM_USERCOUNT + uid, urlData, 16, NULL, 0);
	if (icRet == AEM_INTCOM_RESPONSE_NOTEXIST) return AEM_API_ERR_MESSAGE_DELETE_NOTFOUND;
	return (icRet == AEM_INTCOM_RESPONSE_OK) ? AEM_API_STATUS_OK : AEM_API_ERR_INTERNAL;
}

static unsigned char message_upload(const uint16_t uid, const unsigned char urlData[AEM_API_REQ_DATA_LEN], const unsigned char * const src, const size_t lenSrc) {
	const uint32_t ts = (uint32_t)time(NULL);
	size_t lenMsg = AEM_ENVELOPE_RESERVED_LEN + 6 + lenSrc;
	const size_t padAmount = msg_getPadAmount(lenMsg);
	lenMsg += padAmount;

	unsigned char msg[lenMsg];
	msg[AEM_ENVELOPE_RESERVED_LEN] = padAmount | 32; // 32=UplMsg
	memcpy(msg + AEM_ENVELOPE_RESERVED_LEN + 1, &ts, 4);
	msg[AEM_ENVELOPE_RESERVED_LEN + 5] = urlData[0] & 127; // lenFileName
	memcpy(msg + AEM_ENVELOPE_RESERVED_LEN + 6, src, lenSrc);

	const int32_t icRet = intcom(AEM_INTCOM_SERVER_STO, uid, msg, lenMsg, NULL, 0);
	return (icRet == AEM_INTCOM_RESPONSE_OK) ? AEM_API_STATUS_OK : AEM_API_ERR_INTERNAL;
}

static long readHeaders(void) {
	char buf[1000];
	int ret = recv(AEM_FD_SOCK_CLIENT, buf, 1000, MSG_PEEK);
	if (ret < 10) return -1;

	char * const headersEnd = memmem(buf, ret, "\r\n\r\n", 4);
	if (headersEnd == NULL) return -2;
	*headersEnd = '\0';

	const char *clBegin = (char*)memcasemem((const unsigned char * const)buf, headersEnd - buf, "Content-Length:", 15);
	if (clBegin == NULL || headersEnd - clBegin < 10) return 0; // No body
	clBegin += 15;
	if (*clBegin == ' ') clBegin++;

	const long cl = strtol(clBegin, NULL, 10);
	if (cl < 10) return -4;

	recv(AEM_FD_SOCK_CLIENT, buf, (headersEnd + 4) - buf, 0); // Next recv returns the POST body
	return cl;
}

static void handleContinue(const unsigned char * const req, const size_t lenBody) {
	// Used with Account/Create and Private/Update. Prevents AEM-API from accessing the sensitive request data.
	unsigned char body[AEM_API_REQ_LEN + lenBody];
	if (recv(AEM_FD_SOCK_CLIENT, body + AEM_API_REQ_LEN, lenBody, MSG_WAITALL) != (ssize_t)lenBody) {
		respond404();
		return;
	}
	memcpy(body, req, AEM_API_REQ_LEN);

	// Redo the Account IntCom request, now with the POST body
	unsigned char *icData = NULL;
	const int32_t icRet = intcom(AEM_INTCOM_SERVER_ACC, AEM_INTCOM_OP_POST, body, AEM_API_REQ_LEN + lenBody, &icData, 0);

	if (icRet > AEM_LEN_APIRESP_BASE) {
		setRbk(icData + 1 + AEM_API_REQ_DATA_LEN + AEM_API_BODY_KEYSIZE);
		apiResponse(icData + AEM_LEN_APIRESP_BASE, icRet - AEM_LEN_APIRESP_BASE);
	} else {
		respond500();
	}

	if (icData != NULL) free(icData);
}

static void handleGet(const int cmd, const uint16_t uid, const unsigned char urlData[AEM_API_REQ_DATA_LEN], const unsigned char * const icData, const size_t lenIcData) {
	switch (cmd) {
		case AEM_API_MESSAGE_BROWSE:
			message_browse(uid, urlData, icData, lenIcData);
		break;

		case AEM_API_MESSAGE_DELETE: {
			const unsigned char rb = message_delete(uid, urlData);
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
	if (recv(AEM_FD_SOCK_CLIENT, body, lenBody, MSG_WAITALL) != (ssize_t)lenBody)
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

void aem_api_process(unsigned char req[AEM_API_REQ_LEN], const bool isPost) {
	// Forward the request to Account
	unsigned char *icData = NULL;
	int32_t icRet = intcom(AEM_INTCOM_SERVER_ACC, isPost? AEM_INTCOM_OP_POST : AEM_INTCOM_OP_GET, (const unsigned char * const)req, AEM_API_REQ_LEN, &icData, 0);

	if (icRet == AEM_INTCOM_RESPONSE_AUTHFAIL) {respond403(); return;}

	if (icRet < AEM_LEN_APIRESP_BASE && (!isPost || icRet != AEM_INTCOM_RESPONSE_CONTINUE)) {
		if (icData != NULL) free(icData);
		syslog(LOG_INFO, "Invalid response from Account: %d", icRet);
		respond500();
		return;
	}

	// The request is authentic. Download the headers.
	const long lenBody = readHeaders();
	if (lenBody < 0 || lenBody > (AEM_MSG_SRC_MAXSIZE - 1) || (lenBody < 1 && isPost) || (lenBody > 0 && !isPost)) {
		if (icRet == AEM_INTCOM_RESPONSE_CONTINUE) {
			respond400();
		} else {
			setRbk(icData + 1 + AEM_API_REQ_DATA_LEN + AEM_API_BODY_KEYSIZE);
			const unsigned char rb = AEM_API_ERR_POST;
			apiResponse(&rb, 1);
		}
	} else if (icRet == AEM_INTCOM_RESPONSE_CONTINUE) {
		return (isPost && lenBody < 99999) ? handleContinue(req, lenBody) : respond500();
	} else {
		const int cmd = icData[0] & 15;
		const int flags = icData[0] >> 4;
		setRbk(icData + 1 + AEM_API_REQ_DATA_LEN + AEM_API_BODY_KEYSIZE);
		const struct aem_req * const req_s = (struct aem_req*)req;

		if (isPost) {
			unsigned char * const postBody = malloc(lenBody);
			if (postBody == NULL) {
				syslog(LOG_ERR, "Failed malloc");
			} else {
				const unsigned char rb = handlePost(cmd, flags, req_s->uid, icData + 1, icData + 1 + AEM_API_REQ_DATA_LEN, icData + AEM_LEN_APIRESP_BASE, icRet - AEM_LEN_APIRESP_BASE, postBody, lenBody);
				free(postBody);
				apiResponse(&rb, 1);
			}
		} else {
			handleGet(cmd, req_s->uid, icData + 1, icData + AEM_LEN_APIRESP_BASE, icRet - AEM_LEN_APIRESP_BASE);
		}
	}

	sodium_memzero(icData, icRet);
	free(icData);
	clrRbk();
}
