#include <string.h>
#include <sys/socket.h>
#include <syslog.h>
#include <unistd.h>

#include <sodium.h>

#include "../Global.h"
#include "../Common/AEM_KDF.h"
#include "../Common/GetKey.h"
#include "../Common/memeq.h"

#include "manager.h"

#include "mp.h"

#define AEM_MNG_CMD_NOOP  0
#define AEM_MNG_CMD_SPAWN 1
#define AEM_MNG_CMD_TERM  2

static unsigned char mpk[AEM_KDF_MPK_KEYLEN];

int setupMp(void) {
	setupManager();
	return getKey(mpk);
}

void clearMp(void) {
	clearManager();
	sodium_memzero(mpk, AEM_KDF_MPK_KEYLEN);
}

static long readHeaders(void) {
	unsigned char buf[1000];
	int ret = recv(AEM_FD_SOCK_CLIENT, buf, 1000, MSG_PEEK);
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

	recv(AEM_FD_SOCK_CLIENT, buf, (headersEnd + 4) - buf, 0); // Next recv returns the POST body
	return cl;
}

void respondClient(void) {
	// Manager Protocol URLs are the same length as API requests (56 chars), making requests impossible to tell apart based on size
	struct {
		uint64_t ignore1: 6;
		uint64_t binTs: 42;
		uint64_t enc1: 16;
		uint16_t enc2;
		unsigned char mac[32];
		uint16_t ignore2;
		uint32_t dec_cmd: 5;
		uint32_t dec_data: 27;
	} r;

	char raw[62];
	if (recv(AEM_FD_SOCK_CLIENT, raw, 62, 0) != 62) {
		syslog(LOG_WARNING, "Manager Protocol: Failed recv: %m");
		close(AEM_FD_SOCK_CLIENT);
		return;
	}

	char *b64 = NULL;
	bool isPost = false;
	if (raw[0] == 'G' || raw[1] == 'E' || raw[2] == 'T' || raw[3] == ' ' || raw[4] == '/') {
		b64 = raw + 5;
	} else if (raw[0] == 'P' || raw[1] == 'O' || raw[2] == 'S' || raw[3] == 'T' || raw[4] == ' ' || raw[5] == '/') {
		b64 = raw + 6;
		isPost = true;
	} else {
		syslog(LOG_WARNING, "Manager Protocol: Invalid request");
		close(AEM_FD_SOCK_CLIENT);
		return;		
	}

	b64[0] = 'A'; // Set by client to '~' to allow the reverse proxy to distinguish between requests to Manager and API
	size_t decodedLen = 0;
	sodium_base642bin((unsigned char*)&r, 48, b64, 56, NULL, &decodedLen, NULL, sodium_base64_VARIANT_URLSAFE);
	if (decodedLen != 42) {
		syslog(LOG_WARNING, "Manager Protocol: Invalid base64");
		return;
	}

	unsigned char aead_nonce[crypto_aead_aegis256_NPUBBYTES];
	memcpy(aead_nonce, &r, 6);
	memset(aead_nonce + 6, '\0', crypto_aead_aegis256_NPUBBYTES - 6);

	if (crypto_aead_aegis256_decrypt((unsigned char*)&r + 44, NULL, NULL, (unsigned char*)&r + 6, 4 + crypto_aead_aegis256_ABYTES, NULL, 0, aead_nonce, mpk) != 0) {
		syslog(LOG_WARNING, "Manager Protocol: Failed to decrypt URL");
		return;
	}

	long lenBody = isPost? readHeaders() : 0;
	if (isPost) {
//		AEM_MNG_CMD_NOOP: break;

		if (lenBody != 289) {
			syslog(LOG_WARNING, "Manager Protocol: Invalid post length: %d", lenBody);
			return;
		}

		unsigned char enc[289];
		unsigned char dec[257];
		recv(AEM_FD_SOCK_CLIENT, enc, 289, MSG_WAITALL);
		aead_nonce[0] |= 64;
		if (crypto_aead_aegis256_decrypt(dec, NULL, NULL, enc, 289, NULL, 0, aead_nonce, mpk) != 0) {
			syslog(LOG_WARNING, "Manager Protocol: Failed to decrypt body");
			return;
		}
		aead_nonce[0] ^= 64;
		lenBody -= dec[0] + crypto_aead_aegis256_ABYTES + 1;

		const int processType = r.dec_data & 15;
		switch (processType) {
			case AEM_PROCESSTYPE_ACC:
			case AEM_PROCESSTYPE_STO: {
				if (lenBody != 32 + AEM_KDF_SUB_KEYLEN) {
					syslog(LOG_WARNING, "Manager Protocol: Invalid type-%d body length: %d", processType, lenBody);
					return;
				}
				const int ret = process_spawn(processType, dec + 1, dec + 33);
				if (ret != 0) {
					syslog(LOG_WARNING, "Manager Protocol: Failed spawning type-%d: %d", processType, ret);
					return;
				}
			break;}

			case AEM_PROCESSTYPE_DLV:
			case AEM_PROCESSTYPE_ENQ:
			case AEM_PROCESSTYPE_REG:
			case AEM_PROCESSTYPE_WEB: {
				if (lenBody != 32) {
					syslog(LOG_WARNING, "Manager Protocol: Invalid type-%d body length: %d", processType, lenBody);
					return;
				}
				const int ret = process_spawn(processType, dec + 1, NULL);
				if (ret != 0) {
					syslog(LOG_WARNING, "Manager Protocol: Failed spawning type-%d: %d", processType, ret);
					return;
				}
			break;}

			case AEM_PROCESSTYPE_API: {
				if (lenBody != 32 + AEM_KDF_SUB_KEYLEN) {
					syslog(LOG_WARNING, "Manager Protocol: Invalid API body length: %d", processType, lenBody);
					return;
				}
				const int count = r.dec_data >> 4;
				if (count < 1 || count > 256) {
					syslog(LOG_WARNING, "Manager Protocol: Invalid API count: %d", count);
					return;
				}
				for (int i = 0; i < count; i++) {
					const int ret = process_spawn(processType, dec + 1, dec + 33);
					if (ret != 0) {
						syslog(LOG_WARNING, "Manager Protocol: Failed spawning API: %d", ret);
						return;
					}
				}
			break;}

			case AEM_PROCESSTYPE_MTA: {
				if (lenBody != 32) {
					syslog(LOG_WARNING, "Manager Protocol: Invalid MTA body length: %d", lenBody);
					return;
				}
				const int count = r.dec_data >> 4;
				if (count < 1 || count > 256) {
					syslog(LOG_WARNING, "Manager Protocol: Invalid MTA count: %d", count);
					return;
				}
				for (int i = 0; i < count; i++) {
					const int ret = process_spawn(processType, dec + 1, NULL);
					if (ret != 0) {
						syslog(LOG_WARNING, "Manager Protocol: Failed spawning MTA: %d", ret);
						return;
					}
				}
			break;}

			default: syslog(LOG_WARNING, "Manager Protocol: Invalid data: %d", r.dec_data); return;
		}
	} else {
		switch (r.dec_cmd) {
			case AEM_MNG_CMD_NOOP: break;

			default:
				syslog(LOG_WARNING, "Manager Protocol: Invalid GET command: %d", r.dec_cmd);
				return;
		}
	}

	unsigned char src[257];
	src[0] = 191;
	getProcessInfo(src + 1);
	bzero(src + 1 + AEM_PROCESSINFO_BYTES, 256 - AEM_PROCESSINFO_BYTES);

	unsigned char res[41 + 257 + crypto_aead_aegis256_ABYTES];
	memcpy(res, "HTTP/1.0 200 aem\r\nContent-Length: 289\r\n\r\n", 41);

	aead_nonce[0] |= 128; // Response
	crypto_aead_aegis256_encrypt(res + 41, NULL, src, 257, NULL, 0, NULL, aead_nonce, mpk);
	send(AEM_FD_SOCK_CLIENT, res, 41 + 257 + crypto_aead_aegis256_ABYTES, 0);
}
