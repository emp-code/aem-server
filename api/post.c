#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <sodium.h>

#include "../Global.h"
#include "../Common/Message.h"
#include "../Common/api_req.h"
#include "../Common/memeq.h"
#include "../IntCom/Client.h"

#include "Error.h"
#include "Respond.h"

#include "post.h"

//#include "../Common/Message.c"

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
		lenResponse += lenAccData;
		response = malloc(lenResponse);
		if (response == NULL) {
			syslog(LOG_INFO, "Failed allocation");
			const unsigned char rb = AEM_API_ERR_INTERNAL;
			apiResponse(&rb, 1);
			return;
		}

		memcpy(response, accData, lenAccData);
		memcpy(response + lenAccData, stoData, stoRet);
		free(stoData);
	} else {
		response = stoData;
	}

	apiResponse(response, lenResponse);
	free(response);
}

static unsigned char message_create(const unsigned char * const cuid, const size_t lenCuid, const unsigned char urlData[AEM_API_REQ_DATA_LEN], const unsigned char * const src, const size_t lenSrc) {
	if (lenCuid == 1) return cuid[0];
	if (lenCuid != 2) return AEM_API_ERR_INTERNAL;
	const uint16_t uid = *(const uint16_t*)cuid;
	if (uid >= AEM_USERCOUNT) return AEM_API_ERR_INTERNAL;

	// urlData: 0..9 from addr32
	// urlData: 10..19 to addr32
	//	urlData[20] & 128 fromShield
	//	urlData[20] & 64 toShield

	const uint32_t ts = (uint32_t)time(NULL);
	size_t lenMsg = AEM_ENVELOPE_RESERVED_LEN + 58 + lenSrc;
	const size_t padAmount = msg_getPadAmount(lenMsg);
	lenMsg += padAmount;

	unsigned char msg[lenMsg];
	msg[AEM_ENVELOPE_RESERVED_LEN] = padAmount | 16; // 16=IntMsg
	memcpy(msg + AEM_ENVELOPE_RESERVED_LEN + 1, &ts, 4);
	msg[AEM_ENVELOPE_RESERVED_LEN + 5] = ((urlData[20] & 192) >> 4); // IntMsg InfoByte: 0=Plain; 8/4: FromShield/ToShield; TODO: 0-3: SenderLevel
	memcpy(msg + AEM_ENVELOPE_RESERVED_LEN + 6, urlData, 20); // From/To Addr32
	bzero(msg + AEM_ENVELOPE_RESERVED_LEN + 26, 32); // TODO: APK
	memcpy(msg + AEM_ENVELOPE_RESERVED_LEN + 58, src, lenSrc);

	const int32_t icRet = intcom(AEM_INTCOM_SERVER_STO, uid, msg, lenMsg, NULL, 0);
	return (icRet == AEM_INTCOM_RESPONSE_OK) ? AEM_API_STATUS_OK : AEM_API_ERR_INTERNAL;
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

static int handlePost(const int cmd, const uint16_t uid, const unsigned char urlData[AEM_API_REQ_DATA_LEN], const unsigned char requestBodyKey[AEM_API_BODY_KEYSIZE], const unsigned char * const icData, const size_t lenIcData, unsigned char * const body, const size_t lenBody) {
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
		case AEM_API_MESSAGE_CREATE: return message_create(icData, lenIcData, urlData, decBody + AEM_API_REQ_LEN, lenBody);
		case AEM_API_MESSAGE_UPLOAD: return message_upload(uid, urlData, decBody + AEM_API_REQ_LEN, lenBody);
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
		const int cmd = icData[0];
		setRbk(icData + 1 + AEM_API_REQ_DATA_LEN + AEM_API_BODY_KEYSIZE);
		const struct aem_req * const req_s = (struct aem_req*)req;

		if (isPost) {
			unsigned char * const postBody = malloc(lenBody);
			if (postBody == NULL) {
				syslog(LOG_ERR, "Failed malloc");
			} else {
				handlePost(cmd, req_s->uid, icData + 1, icData + 1 + AEM_API_REQ_DATA_LEN, icData + AEM_LEN_APIRESP_BASE, icRet - AEM_LEN_APIRESP_BASE, postBody, lenBody);
				free(postBody);
			}
		} else {
			handleGet(cmd, req_s->uid, icData + 1, icData + AEM_LEN_APIRESP_BASE, icRet - AEM_LEN_APIRESP_BASE);
		}
	}

	sodium_memzero(icData, icRet);
	free(icData);
	clrRbk();
}
