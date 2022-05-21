#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <syslog.h>
#include <unistd.h>

#include <sodium.h>

#include "../Data/internal.h"
#include "../Global.h"

#include "IntCom_Common.h"

#if defined(AEM_ACCOUNT)
	#define AEM_INTCOM_TYPE AEM_INTCOM_TYPE_ACCOUNT
	#include "../account/IntCom_Action.h"
#elif defined(AEM_ENQUIRY)
	#define AEM_INTCOM_TYPE AEM_INTCOM_TYPE_ENQUIRY
	#include "../enquiry/IntCom_Action.h"
#elif defined(AEM_STORAGE)
	#define AEM_INTCOM_TYPE AEM_INTCOM_TYPE_STORAGE
	#include "../storage/IntCom_Action.h"
#endif

#include "IntCom_Server.h"

static bool terminate = false;

void tc_term(void) {
	terminate = true;
}

static bool peerOk(const int sock) {
	struct ucred peer;
	unsigned int lenUc = sizeof(struct ucred);
	if (getsockopt(sock, SOL_SOCKET, SO_PEERCRED, &peer, &lenUc) == -1) return false;
	return (peer.gid == getgid() && peer.uid == getuid());
}

static int bindSocket(const int sock) {
	struct sockaddr_un sa;
	sa.sun_family = AF_UNIX;
	memcpy(sa.sun_path,
#if defined(AEM_ACCOUNT)
		AEM_SOCKPATH_ACCOUNT
#elif defined(AEM_ENQUIRY)
		AEM_SOCKPATH_ENQUIRY
#elif defined(AEM_STORAGE)
		AEM_SOCKPATH_STORAGE
#endif
		, AEM_SOCKPATH_LEN);

	return bind(sock, (struct sockaddr*)&sa, sizeof(sa.sun_family) + 4);
}

static const unsigned char *intcom_keys[] = {
#if defined(AEM_ACCOUNT)
	AEM_KEY_INTCOM_ACCOUNT_API,
	AEM_KEY_INTCOM_ACCOUNT_MTA
#elif defined(AEM_ENQUIRY)
	AEM_KEY_INTCOM_ENQUIRY_API,
	AEM_KEY_INTCOM_ENQUIRY_MTA
#elif defined(AEM_STORAGE)
	AEM_KEY_INTCOM_STORAGE_API,
	AEM_KEY_INTCOM_STORAGE_MTA,
	AEM_KEY_INTCOM_STORAGE_ACC
#endif
};

void takeConnections(void) {
	const int sockListen = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (bindSocket(sockListen) != 0) {syslog(LOG_ERR, "Failed bindSocket(): %m"); return;}
	listen(sockListen, 50);

	while (!terminate) {
		const int sock = accept4(sockListen, NULL, NULL, SOCK_CLOEXEC);
		if (sock < 0) continue;

		if (!peerOk(sock)) {
			syslog(LOG_WARNING, "Connection rejected from invalid peer");
			close(sock);
			continue;
		}

		const size_t lenEncHdr = 5 + crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES;
		unsigned char encHdr[lenEncHdr];
		if (recv(sock, encHdr, lenEncHdr, 0) != lenEncHdr) {syslog(LOG_ERR, "IntCom[S]: Failed sending header: %m"); close(sock); continue;}

		switch (encHdr[0]) {
			case AEM_IDENTIFIER_API: break;
			case AEM_IDENTIFIER_MTA: break;
#ifdef AEM_STORAGE
			case AEM_IDENTIFIER_ACC: break;
#endif
			default:
				syslog(LOG_WARNING, "Invalid identifier: %u", encHdr[0]);
				close(sock);
				continue;
		}

		uint32_t hdr;
		if (crypto_secretbox_open_easy((unsigned char*)&hdr, encHdr + 1 + crypto_secretbox_NONCEBYTES, sizeof(uint32_t) + crypto_secretbox_MACBYTES, encHdr + 1, intcom_keys[encHdr[0]]) != 0) {
			syslog(LOG_ERR, "IntCom[S]: Failed decrypting header: %m");
			close(sock);
			continue;
		}

		const uint8_t type = hdr >> 24;
		const size_t lenMsg = hdr & UINT24_MAX;

		unsigned char *res = NULL;
		int32_t resCode = AEM_INTCOM_RESPONSE_ERR;

		if (lenMsg > 0) {
			unsigned char * const msg = sodium_malloc(lenMsg + crypto_secretbox_MACBYTES);
			if (msg == NULL) {syslog(LOG_ERR, "Failed allocation"); close(sock); continue;}
			if (recv(sock, msg, lenMsg + crypto_secretbox_MACBYTES, MSG_WAITALL) != (ssize_t)lenMsg + crypto_secretbox_MACBYTES) {syslog(LOG_ERR, "IntCom[S]: Failed receiving message: %m"); close(sock); sodium_free(msg); continue;}

			sodium_increment(encHdr + 1, crypto_secretbox_NONCEBYTES);
			if (crypto_secretbox_open_easy(msg, msg, lenMsg + crypto_secretbox_MACBYTES, encHdr + 1, intcom_keys[encHdr[0]]) != 0) {
				syslog(LOG_ERR, "IntCom[S]: Failed decrypting message: %m");
				close(sock);
				sodium_free(msg);
				continue;
			}

			switch (encHdr[0]) {
				case AEM_IDENTIFIER_API: resCode = conn_api(type, msg, lenMsg, &res); break;
				case AEM_IDENTIFIER_MTA: resCode = conn_mta(type, msg, lenMsg, &res); break;
#ifdef AEM_STORAGE
				case AEM_IDENTIFIER_ACC: resCode = conn_acc(type, msg, lenMsg, &res);
#endif
			}

			sodium_free(msg);
		} else {
			switch (encHdr[0]) {
				case AEM_IDENTIFIER_API: resCode = conn_api(type, NULL, 0, &res); break;
				case AEM_IDENTIFIER_MTA: resCode = conn_mta(type, NULL, 0, &res); break;
#ifdef AEM_STORAGE
				case AEM_IDENTIFIER_ACC: resCode = conn_acc(type, NULL, 0, &res);
#endif
			}
		}

		if (res == NULL && resCode > 0) {
			resCode = AEM_INTCOM_RESPONSE_ERR;
		} else if (res != NULL && resCode <= 0) {
			sodium_free(res);
		}

		sodium_increment(encHdr + 1, crypto_secretbox_NONCEBYTES);
		const size_t lenResHdr = sizeof(int32_t) + crypto_secretbox_MACBYTES;
		unsigned char resHdr[lenResHdr];
		crypto_secretbox_easy(resHdr, (const unsigned char*)&resCode, sizeof(int32_t), encHdr + 1, intcom_keys[encHdr[0]]);
		if (send(sock, resHdr, lenResHdr, 0) != lenResHdr) {syslog(LOG_ERR, "IntCom[S]: Failed sending header: %m"); close(sock); continue;}

		if (resCode > 0) {
			sodium_increment(encHdr + 1, crypto_secretbox_NONCEBYTES);
			unsigned char mac[crypto_secretbox_MACBYTES];
			crypto_secretbox_detached(res, mac, res, resCode, encHdr + 1, intcom_keys[encHdr[0]]);

			if (send(sock, mac, crypto_secretbox_MACBYTES, MSG_MORE) != crypto_secretbox_MACBYTES || send(sock, res, resCode, 0) != resCode) {
				syslog(LOG_ERR, "IntCom[S]: Failed sending message: %m");
				close(sock);
				sodium_free(res);
				continue;
			}

			sodium_free(res);
		}

		close(sock);
	}

	close(sockListen);
}
