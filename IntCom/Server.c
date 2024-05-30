#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <syslog.h>
#include <unistd.h>

#include <sodium.h>

#include "../Global.h"

#if defined(AEM_ACCOUNT)
	#include "../account/IntCom_Action.h"
#elif defined(AEM_ENQUIRY)
	#include "../enquiry/IntCom_Action.h"
#elif defined(AEM_STORAGE)
	#include "../storage/IntCom_Action.h"
#else
	#error No IntCom_Action defined
#endif

#include "peerok.h"

#include "Server.h"

static unsigned char intcom_keys[AEM_INTCOM_CLIENT_COUNT][crypto_aead_aegis256_KEYBYTES]; // The server's keys for each client

static volatile sig_atomic_t terminate = 0;
int sockListen = -1;
int sockClient = -1;

void sigTerm(const int s) {
	terminate = 1;
	close(sockListen);
	close(sockClient);
}

void intcom_setKeys_server(const unsigned char newKeys[AEM_INTCOM_CLIENT_COUNT][crypto_aead_aegis256_KEYBYTES]) {
	memcpy(intcom_keys, newKeys, AEM_INTCOM_CLIENT_COUNT * crypto_aead_aegis256_KEYBYTES);
}

static int bindSocket(const int sock) {
	struct sockaddr_un sa;
	sa.sun_family = AF_UNIX;
	memcpy(sa.sun_path,
#if defined(AEM_ACCOUNT)
		AEM_INTCOM_SOCKPATH_ACCOUNT
#elif defined(AEM_ENQUIRY)
		AEM_INTCOM_SOCKPATH_ENQUIRY
#elif defined(AEM_STORAGE)
		AEM_INTCOM_SOCKPATH_STORAGE
#else
	#error No path for bindSocket()
#endif
		, AEM_INTCOM_SOCKPATH_LEN);

	return bind(sock, (struct sockaddr*)&sa, sizeof(sa.sun_family) + AEM_INTCOM_SOCKPATH_LEN);
}

void intcom_serve(void) {
	sockListen = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (bindSocket(sockListen) != 0) {syslog(LOG_ERR, "Failed bindSocket(): %m"); return;}
	listen(sockListen, 50);

	while (terminate == 0) {
		sockClient = accept4(sockListen, NULL, NULL, SOCK_CLOEXEC);
		if (sockClient < 0) continue;

		if (!peerOk(sockClient)) {
			syslog(LOG_WARNING, "IntCom[S]: Connection rejected from invalid peer");
			close(sockClient);
			continue;
		}

		const size_t lenEncHdr = 1 + (sizeof(uint32_t) * 2) + crypto_aead_aegis256_NPUBBYTES + crypto_aead_aegis256_ABYTES;
		unsigned char encHdr[lenEncHdr];
		if (recv(sockClient, encHdr, lenEncHdr, 0) != (ssize_t)lenEncHdr) {syslog(LOG_ERR, "IntCom[S]: Failed receiving header: %m"); close(sockClient); continue;}

		if (encHdr[0] >= AEM_INTCOM_CLIENT_COUNT || sodium_is_zero(intcom_keys[encHdr[0]], crypto_aead_aegis256_KEYBYTES)) {
			syslog(LOG_WARNING, "IntCom[S]: Invalid identifier: %u", encHdr[0]);
			close(sockClient);
			continue;
		}

		uint32_t hdr[2];
		if (crypto_aead_aegis256_decrypt((unsigned char*)hdr, NULL, NULL, encHdr + 1 + crypto_aead_aegis256_NPUBBYTES, (sizeof(uint32_t) * 2) + crypto_aead_aegis256_ABYTES, NULL, 0, encHdr + 1, intcom_keys[encHdr[0]]) != 0) {
			syslog(LOG_ERR, "IntCom[S]: Failed decrypting header, type %u", encHdr[0]);
			close(sockClient);
			continue;
		}

		const uint32_t operation = hdr[0];
		const size_t lenMsg = hdr[1];

		unsigned char *res = NULL;
		int32_t resCode = AEM_INTCOM_RESPONSE_ERR;

		if (lenMsg > 0) {
			unsigned char * const encMsg = malloc(lenMsg + crypto_aead_aegis256_ABYTES);
			if (encMsg == NULL) {syslog(LOG_ERR, "Failed allocation"); close(sockClient); continue;}
			if (recv(sockClient, encMsg, lenMsg + crypto_aead_aegis256_ABYTES, MSG_WAITALL) != (ssize_t)lenMsg + crypto_aead_aegis256_ABYTES) {syslog(LOG_ERR, "IntCom[S]: Failed receiving message: %m"); close(sockClient); free(encMsg); continue;}

			unsigned char * const msg = malloc(lenMsg);
			if (msg == NULL) {syslog(LOG_ERR, "Failed allocation"); close(sockClient); free(encMsg); continue;}

			sodium_increment(encHdr + 1, crypto_aead_aegis256_NPUBBYTES);
			if (crypto_aead_aegis256_decrypt(msg, NULL, NULL, encMsg, lenMsg + crypto_aead_aegis256_ABYTES, NULL, 0, encHdr + 1, intcom_keys[encHdr[0]]) != 0) {
				syslog(LOG_ERR, "IntCom[S]: Failed decrypting message: %m");
				close(sockClient);
				free(encMsg);
				free(msg);
				continue;
			}

			sodium_memzero(encMsg, lenMsg);
			free(encMsg);

			switch (encHdr[0]) {
				case AEM_INTCOM_CLIENT_API: resCode = conn_api(operation, msg, lenMsg, &res); break;
#if defined(AEM_ACCOUNT)
				case AEM_INTCOM_CLIENT_MTA: resCode = conn_mta(operation, msg, lenMsg, &res); break;
#elif defined(AEM_ENQUIRY)
				case AEM_INTCOM_CLIENT_DLV: resCode = conn_dlv(operation, msg, lenMsg, &res); break;
#elif defined(AEM_STORAGE)
				case AEM_INTCOM_CLIENT_ACC: resCode = conn_acc(operation, msg, lenMsg, &res); break;
				case AEM_INTCOM_CLIENT_DLV: resCode = conn_dlv(operation, msg, lenMsg); break;
#endif
				default: syslog(LOG_ERR, "Unhandled client (Msg): %u", encHdr[0]);
			}

			sodium_memzero(msg, lenMsg);
			free(msg);
		} else {
			switch (encHdr[0]) {
				case AEM_INTCOM_CLIENT_API: resCode = conn_api(operation, NULL, 0, &res); break;
#if defined(AEM_STORAGE)
				case AEM_INTCOM_CLIENT_ACC: resCode = conn_acc(operation, NULL, 0, &res); break;
#endif
#if defined(AEM_ACCOUNT)
				case AEM_INTCOM_CLIENT_STO: resCode = conn_sto(operation, &res); break;
#endif
				default: syslog(LOG_ERR, "Unhandled client (No-Msg): %u", encHdr[0]);
			}
		}

		if (res == NULL && resCode > 0) {
			resCode = AEM_INTCOM_RESPONSE_ERR;
		} else if (res != NULL && resCode <= 0) {
			free(res);
		}

		sodium_increment(encHdr + 1, crypto_aead_aegis256_NPUBBYTES);
		const size_t lenResHdr = sizeof(int32_t) + crypto_aead_aegis256_ABYTES;
		unsigned char resHdr[lenResHdr];
		crypto_aead_aegis256_encrypt(resHdr, NULL, (const unsigned char*)&resCode, sizeof(int32_t), NULL, 0, NULL, encHdr + 1, intcom_keys[encHdr[0]]);
		if (send(sockClient, resHdr, lenResHdr, 0) != lenResHdr) {syslog(LOG_ERR, "IntCom[S]: Failed sending header: %m"); close(sockClient); continue;}

		if (resCode > 0) {
			sodium_increment(encHdr + 1, crypto_aead_aegis256_NPUBBYTES);

			unsigned char * const encRes = malloc(resCode + crypto_aead_aegis256_ABYTES);
			if (encRes == NULL) {
				syslog(LOG_ERR, "IntCom[S]: Failed allocation");
				close(sockClient);
				free(res);
				continue;
			}

			crypto_aead_aegis256_encrypt(encRes, NULL, res, resCode, NULL, 0, NULL, encHdr + 1, intcom_keys[encHdr[0]]);

			const ssize_t sentBytes = send(sockClient, encRes, resCode + crypto_aead_aegis256_ABYTES, 0);
			if (sentBytes != resCode + crypto_aead_aegis256_ABYTES) {
				syslog(LOG_ERR, "IntCom[S]: Failed sending message (%d/%d): %m", sentBytes, resCode + crypto_aead_aegis256_ABYTES);
				close(sockClient);
				free(encRes);
				free(res);
				continue;
			}

			free(res);
		}

		close(sockClient);
	}
}
