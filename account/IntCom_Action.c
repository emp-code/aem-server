#include <sodium.h>
#include <stddef.h>
#include <stdint.h>
#include <strings.h>
#include <syslog.h>

#include "../Global.h"
#include "../Common/api_req.h"

#include "IO.h"

#include "IntCom_Action.h"

__attribute__((warn_unused_result, nonnull))
int32_t conn_api(const uint32_t operation, unsigned char *msg, size_t lenMsg, unsigned char **res) {
	const bool post = (operation == AEM_INTCOM_OP_POST);
	if (!post && operation != AEM_INTCOM_OP_GET) {
		syslog(LOG_WARNING, "Invalid op (API): %u", operation);
		return AEM_INTCOM_RESPONSE_ERR;
	}

	union aem_req * const req = (union aem_req * const)msg;

	*res = malloc(30720); // 30 KiB (largest response is Account/Browse, ~20 KiB?)
	if (*res == NULL) {syslog(LOG_ERR, "Failed malloc"); return AEM_INTCOM_RESPONSE_ERR;}

	// api_auth adds Decrypted Command, Decrypted UrlData, ReqBodyKey, ResBodyKey (AEM_LEN_APIRESP_BASE bytes)
	const int32_t retAuth = api_auth(*res, req, post);
	if (retAuth != AEM_INTCOM_RESPONSE_OK) return retAuth;

	int32_t icRet = AEM_INTCOM_RESPONSE_ERR;
	if (!post) {
		switch (req->n.cmd) {
			case AEM_API_ACCOUNT_BROWSE: icRet = api_account_browse(*res + AEM_LEN_APIRESP_BASE); break;
			case AEM_API_ACCOUNT_DELETE: icRet = api_account_delete(*res + AEM_LEN_APIRESP_BASE, req->c.data); break;
			case AEM_API_ACCOUNT_PERMIT: icRet = api_account_permit(*res + AEM_LEN_APIRESP_BASE); break;
			case AEM_API_ACCOUNT_UPDATE: icRet = api_account_update(*res + AEM_LEN_APIRESP_BASE, req->c.data); break;
			case AEM_API_ADDRESS_CREATE: icRet = api_address_create(*res + AEM_LEN_APIRESP_BASE, req->c.data); break;
			case AEM_API_ADDRESS_DELETE: icRet = api_address_delete(*res + AEM_LEN_APIRESP_BASE, req->c.data); break;
			case AEM_API_MESSAGE_BROWSE: icRet = api_message_browse(*res + AEM_LEN_APIRESP_BASE, req->n.flags); break;
			case AEM_API_SETTING_LIMITS: icRet = api_setting_limits(*res + AEM_LEN_APIRESP_BASE, req->c.data); break;

			// No action needed
			case AEM_API_MESSAGE_DELETE:
				icRet = 0;
			break;

			default:
				icRet = api_invalid(*res + AEM_LEN_APIRESP_BASE);
				syslog(LOG_INFO, "Unknown API command (GET): %d", req->n.cmd);
		}
	} else {
		switch (req->n.cmd) {
			case AEM_API_ACCOUNT_KEYSET:
			case AEM_API_ADDRESS_UPDATE:
			case AEM_API_PRIVATE_UPDATE: {
				if (lenMsg == AEM_API_REQ_LEN) {
					decreaseLastBinTs();
					icRet = AEM_INTCOM_RESPONSE_CONTINUE;
				} else if (lenMsg > AEM_API_REQ_LEN) {
					// Authenticate and decrypt the POST body
					const size_t lenDecBody = lenMsg - AEM_API_REQ_LEN - crypto_aead_aegis256_ABYTES;
					unsigned char decBody[lenDecBody];
					if (crypto_aead_aegis256_decrypt(decBody, NULL, NULL, msg + AEM_API_REQ_LEN, lenMsg - AEM_API_REQ_LEN, NULL, 0, *res + 4 + AEM_API_REQ_DATA_LEN, *res + 36 + AEM_API_REQ_DATA_LEN) == 0) {
						switch (req->n.cmd) {
							case AEM_API_ACCOUNT_KEYSET: icRet = api_account_keyset(*res + AEM_LEN_APIRESP_BASE, decBody, lenDecBody); break;
							case AEM_API_ADDRESS_UPDATE: icRet = api_address_update(*res + AEM_LEN_APIRESP_BASE, decBody, lenDecBody); break;
							case AEM_API_PRIVATE_UPDATE: icRet = api_private_update(*res + AEM_LEN_APIRESP_BASE, decBody, lenDecBody); break;
						}
					} else icRet = AEM_INTCOM_RESPONSE_AUTH_DECRYPT;
				} else {icRet = AEM_INTCOM_RESPONSE_ERR; syslog(LOG_ERR, "Invalid Continued request from API");}

				// For user privacy, erase all but the response key from our response to AEM-API
				sodium_memzero(*res, AEM_LEN_APIRESP_BASE - AEM_API_BODY_KEYSIZE);
			break;}

			case AEM_API_MESSAGE_CREATE: {
				icRet = api_message_create(*res + AEM_LEN_APIRESP_BASE, req->c.data, req->n.flags);
			break;}

			case AEM_API_MESSAGE_SENDER:
			case AEM_API_MESSAGE_UPLOAD: {
				icRet = 0; // No action needed
			break;}

			default:
				syslog(LOG_INFO, "Unknown API command (POST): %d", req->n.cmd);
				icRet = AEM_INTCOM_RESPONSE_ERR;
		}
	}

	if (icRet < 0) {
		sodium_memzero(*res, AEM_LEN_APIRESP_BASE);
		free(*res);
		*res = NULL;
		return icRet;
	}

	// TODO: For user privacy, erase fields added by api_auth that AEM-API doesn't need to know for whichever particular command
	return AEM_LEN_APIRESP_BASE + icRet;
}

__attribute__((warn_unused_result, nonnull))
int32_t conn_mta(const uint32_t operation, const unsigned char * const msg, const size_t lenMsg, unsigned char **res) {
	if (operation != 0 || lenMsg != 10) {syslog(LOG_ERR, "Invalid request (MTA): %u", operation); return AEM_INTCOM_RESPONSE_ERR;}

	return mta_getUid(msg, res);
}

__attribute__((warn_unused_result, nonnull))
int32_t conn_reg(const uint32_t operation, const unsigned char * const msg, const size_t lenMsg) {
	if (operation != 0 || lenMsg != 84) {syslog(LOG_ERR, "Invalid request (Reg): %u", operation); return AEM_INTCOM_RESPONSE_ERR;}

	return reg_register(msg);
}

__attribute__((warn_unused_result, nonnull))
int32_t conn_sto(const uint32_t operation, unsigned char **res) {
	if (operation >= AEM_USERCOUNT) {syslog(LOG_ERR, "Invalid request from Storage: %u"); return AEM_INTCOM_RESPONSE_ERR;}

	return sto_uid2keys(operation, res);
}
