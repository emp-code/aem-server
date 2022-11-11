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

#if defined(AEM_ACCOUNT)
	#include "../account/IntCom_Action.h"
#elif defined(AEM_ENQUIRY)
	#include "../enquiry/IntCom_Action.h"
#elif defined(AEM_STORAGE)
	#include "../storage/IntCom_Action.h"
#elif defined(AEM_DELIVER)
	#include "../Common/Email.h"
	#include "../deliver/processing.h"
	#include "../deliver/delivery.h"
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
#elif defined(AEM_DELIVER)
		AEM_SOCKPATH_DELIVER
#endif
		, AEM_SOCKPATH_LEN);

	return bind(sock, (struct sockaddr*)&sa, sizeof(sa.sun_family) + 4);
}

#if defined(AEM_ACCOUNT) || defined(AEM_ENQUIRY) || defined(AEM_STORAGE)
static const unsigned char *intcom_keys[] = {
#if defined(AEM_ACCOUNT)
	AEM_KEY_INTCOM_ACCOUNT_API,
	AEM_KEY_INTCOM_ACCOUNT_MTA,
	AEM_KEY_INTCOM_NULL // ACC
#elif defined(AEM_ENQUIRY)
	AEM_KEY_INTCOM_ENQUIRY_API,
	AEM_KEY_INTCOM_ENQUIRY_MTA,
	AEM_KEY_INTCOM_NULL // ACC
#elif defined(AEM_STORAGE)
	AEM_KEY_INTCOM_STORAGE_API,
	AEM_KEY_INTCOM_STORAGE_DLV,
	AEM_KEY_INTCOM_STORAGE_ACC
#endif
};
#endif

#if defined(AEM_ACCOUNT) || defined(AEM_ENQUIRY)
#define AEM_KEY_INTCOM_COUNT 2
#elif defined(AEM_STORAGE)
#define AEM_KEY_INTCOM_COUNT 3
#endif

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

#ifdef AEM_DELIVER // Stream
		crypto_secretstream_xchacha20poly1305_state ss_state;
		unsigned char ss_header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
		if (recv(sock, ss_header, crypto_secretstream_xchacha20poly1305_HEADERBYTES, MSG_WAITALL) != crypto_secretstream_xchacha20poly1305_HEADERBYTES) {close(sock); syslog(LOG_WARNING, "IntCom[SS] Failed receiving header"); continue;}
		if (crypto_secretstream_xchacha20poly1305_init_pull(&ss_state, ss_header, AEM_KEY_INTCOM_STREAM) != 0) {close(sock); syslog(LOG_WARNING, "IntCom[SS] Failed init"); continue;}

		unsigned char ss_tag = 0xFF;
		unsigned char enc[AEM_SMTP_CHUNKSIZE + crypto_secretstream_xchacha20poly1305_ABYTES];

		unsigned char *dec = sodium_malloc(sizeof(struct emailMeta) + sizeof(struct emailInfo) + 4 + AEM_SMTP_MAX_SIZE_BODY);
		dec[sizeof(struct emailMeta) + sizeof(struct emailInfo)] = '\n';

		size_t lenEnc = 0;

		if (
		   recv(sock, &lenEnc, sizeof(size_t), MSG_WAITALL) != sizeof(size_t)
		|| lenEnc != sizeof(struct emailMeta) + crypto_secretstream_xchacha20poly1305_ABYTES
		|| recv(sock, enc, lenEnc, MSG_WAITALL) != (ssize_t)lenEnc
		|| crypto_secretstream_xchacha20poly1305_pull(&ss_state, dec,                            NULL, &ss_tag, enc, sizeof(struct emailMeta) + crypto_secretstream_xchacha20poly1305_ABYTES, NULL, 0) != 0
		|| ss_tag != 0
		|| recv(sock, &lenEnc, sizeof(size_t), MSG_WAITALL) != sizeof(size_t)
		|| lenEnc != sizeof(struct emailInfo) + crypto_secretstream_xchacha20poly1305_ABYTES
		|| recv(sock, enc, lenEnc, MSG_WAITALL) != (ssize_t)lenEnc
		|| crypto_secretstream_xchacha20poly1305_pull(&ss_state, dec + sizeof(struct emailMeta), NULL, &ss_tag, enc, sizeof(struct emailInfo) + crypto_secretstream_xchacha20poly1305_ABYTES, NULL, 0) != 0
		|| ss_tag != 0
		) {
			close(sock);
			syslog(LOG_WARNING, "IntCom[SS] Failed receiving/decrypting metadata");
			sodium_free(dec);
			continue;
		}

		size_t lenBody = 1;
		while(1) {
			if (recv(sock, &lenEnc, sizeof(size_t), 0) != sizeof(size_t)) {
				syslog(LOG_WARNING, "IntCom[SS] Failed receiving message length");
				sodium_free(dec);
				dec = NULL;
				break;
			}

			if (lenEnc == SIZE_MAX) { // Finished
				crypto_secretstream_xchacha20poly1305_rekey(&ss_state);
				break;
			}

			if (lenEnc <= crypto_secretstream_xchacha20poly1305_ABYTES || lenEnc > AEM_SMTP_CHUNKSIZE + crypto_secretstream_xchacha20poly1305_ABYTES) {
				syslog(LOG_WARNING, "IntCom[SS] Invalid message length");
				sodium_free(dec);
				dec = NULL;
				break;
			}

			if (recv(sock, enc, lenEnc, MSG_WAITALL) != (ssize_t)lenEnc) {
				syslog(LOG_WARNING, "IntCom[SS] Failed receiving message");
				sodium_free(dec);
				dec = NULL;
				break;
			}

			if (crypto_secretstream_xchacha20poly1305_pull(&ss_state, dec + sizeof(struct emailMeta) + sizeof(struct emailInfo) + lenBody, NULL, &ss_tag, enc, lenEnc, NULL, 0) != 0 || (ss_tag != 0)) {
				close(sock);
				syslog(LOG_WARNING, "IntCom[SS] Failed decrypting message (%zu bytes)", lenEnc);
				sodium_free(dec);
				dec = NULL;
				break;
			}

			lenBody += lenEnc - crypto_secretstream_xchacha20poly1305_ABYTES;
		}

		if (dec == NULL) {
			close(sock);
			continue;
		}

		// Add final CRLF for DKIM
		dec[sizeof(struct emailMeta) + sizeof(struct emailInfo) + lenBody]     = '\r';
		dec[sizeof(struct emailMeta) + sizeof(struct emailInfo) + lenBody + 1] = '\n';
		lenBody += 2;

		processEmail(dec + sizeof(struct emailMeta) + sizeof(struct emailInfo), &lenBody, (struct emailInfo*)(dec + sizeof(struct emailMeta)));
		deliverMessage((struct emailMeta*)dec, (struct emailInfo*)(dec + sizeof(struct emailMeta)), dec + sizeof(struct emailMeta) + sizeof(struct emailInfo), lenBody);
		sodium_free(dec);

		const int32_t icRet = AEM_INTCOM_RESPONSE_OK; // TODO
		send(sock, &icRet, sizeof(int32_t), 0);
#else
		const size_t lenEncHdr = 5 + crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES;
		unsigned char encHdr[lenEncHdr];
		if (recv(sock, encHdr, lenEncHdr, 0) != (ssize_t)lenEncHdr) {syslog(LOG_ERR, "IntCom[S]: Failed sending header: %m"); close(sock); continue;}

		switch (encHdr[0]) {
			case AEM_IDENTIFIER_API:
			case AEM_IDENTIFIER_MTA: // including AEM_IDENTIFIER_DLV
			case AEM_IDENTIFIER_ACC: break;
			default:
				syslog(LOG_WARNING, "Invalid identifier: %u", encHdr[0]);
				close(sock);
				continue;
		}

		if (encHdr[0] >= AEM_KEY_INTCOM_COUNT) {
			syslog(LOG_ERR, "IntCom[S]: Invalid header: %d", encHdr[0]);
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
#if defined(AEM_ACCOUNT) || defined(AEM_DELIVER)
				case AEM_IDENTIFIER_MTA: resCode = conn_mta(type, msg, lenMsg, &res); break;
#elif defined(AEM_STORAGE)
				case AEM_IDENTIFIER_ACC: resCode = conn_acc(type, msg, lenMsg, &res); break;
				case AEM_IDENTIFIER_DLV: resCode = conn_dlv(type, msg, lenMsg, &res); break;
#endif
			}

			sodium_free(msg);
		} else {
			switch (encHdr[0]) {
				case AEM_IDENTIFIER_API: resCode = conn_api(type, NULL, 0, &res); break;
#ifdef AEM_DELIVER
				case AEM_IDENTIFIER_MTA: resCode = conn_mta(type, NULL, 0, &res); break;
#elif defined(AEM_STORAGE)
				case AEM_IDENTIFIER_ACC: resCode = conn_acc(type, NULL, 0, &res); break;
				case AEM_IDENTIFIER_DLV: resCode = conn_dlv(type, NULL, 0, &res); break;
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
#endif

		close(sock);
	}

	close(sockListen);
}
