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

#include "../Common/Email.h"
#include "../deliver/deliver.h"

#include "Stream_Server.h"

struct dlvEmail {
	struct emailMeta meta;
	struct emailInfo info;
	unsigned char src[AEM_SMTP_MAX_SIZE_BODY];
	size_t lenSrc;
};

static unsigned char intcom_key[crypto_secretstream_xchacha20poly1305_KEYBYTES];

static volatile sig_atomic_t terminate = 0;
int sockListen = -1;
int sock = -1;

void sigTerm() {
	terminate = 1;
	close(sockListen);
	close(sock);
}

void intcom_setKey_stream(const unsigned char newKey[crypto_secretstream_xchacha20poly1305_KEYBYTES]) {
	memcpy(intcom_key, newKey, crypto_secretstream_xchacha20poly1305_KEYBYTES);
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
	memcpy(sa.sun_path, AEM_INTCOM_SOCKPATH_DELIVER, AEM_INTCOM_SOCKPATH_LEN);

	return bind(sock, (struct sockaddr*)&sa, sizeof(sa.sun_family) + AEM_INTCOM_SOCKPATH_LEN);
}

void intcom_serve_stream(void) {
	sockListen = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (bindSocket(sockListen) != 0) {syslog(LOG_ERR, "Failed bindSocket(): %m"); return;}
	listen(sockListen, 50);

	struct dlvEmail *dlv = malloc(sizeof(struct dlvEmail));
	if (dlv == NULL) {syslog(LOG_ERR, "Failed allocation"); return;}

	while (terminate == 0) {
		sock = accept4(sockListen, NULL, NULL, SOCK_CLOEXEC);
		if (sock < 0) continue;

		if (!peerOk(sock)) {
			syslog(LOG_WARNING, "Connection rejected from invalid peer");
			close(sock);
			continue;
		}

		crypto_secretstream_xchacha20poly1305_state ss_state;
		unsigned char ss_header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
		if (recv(sock, ss_header, crypto_secretstream_xchacha20poly1305_HEADERBYTES, MSG_WAITALL) != crypto_secretstream_xchacha20poly1305_HEADERBYTES) {close(sock); syslog(LOG_WARNING, "IntCom[SS] Failed receiving header"); continue;}
		if (crypto_secretstream_xchacha20poly1305_init_pull(&ss_state, ss_header, intcom_key) != 0) {close(sock); syslog(LOG_WARNING, "IntCom[SS] Failed init"); continue;}

		unsigned char ss_tag = 0xFF;
		unsigned char enc[AEM_SMTP_CHUNKSIZE + crypto_secretstream_xchacha20poly1305_ABYTES];

		size_t lenEnc = 0;

		if (
		   recv(sock, &lenEnc, sizeof(size_t), MSG_WAITALL) != sizeof(size_t)
		|| lenEnc != sizeof(struct emailMeta) + crypto_secretstream_xchacha20poly1305_ABYTES
		|| recv(sock, enc, lenEnc, MSG_WAITALL) != (ssize_t)lenEnc
		|| crypto_secretstream_xchacha20poly1305_pull(&ss_state, (unsigned char*)&dlv->meta, NULL, &ss_tag, enc, sizeof(struct emailMeta) + crypto_secretstream_xchacha20poly1305_ABYTES, NULL, 0) != 0
		|| ss_tag != 0
		|| recv(sock, &lenEnc, sizeof(size_t), MSG_WAITALL) != sizeof(size_t)
		|| lenEnc != sizeof(struct emailInfo) + crypto_secretstream_xchacha20poly1305_ABYTES
		|| recv(sock, enc, lenEnc, MSG_WAITALL) != (ssize_t)lenEnc
		|| crypto_secretstream_xchacha20poly1305_pull(&ss_state, (unsigned char*)&dlv->info, NULL, &ss_tag, enc, sizeof(struct emailInfo) + crypto_secretstream_xchacha20poly1305_ABYTES, NULL, 0) != 0
		|| ss_tag != 0
		) {
			close(sock);
			syslog(LOG_WARNING, "IntCom[SS] Failed receiving/decrypting metadata");
			continue;
		}

		dlv->src[0] = '\n';
		dlv->lenSrc = 1;

		while(1) {
			if (recv(sock, &lenEnc, sizeof(size_t), 0) != sizeof(size_t)) {
				syslog(LOG_WARNING, "IntCom[SS] Failed receiving message length");
				break;
			}

			if (lenEnc == SIZE_MAX || dlv->lenSrc + (lenEnc - crypto_secretstream_xchacha20poly1305_ABYTES) > AEM_SMTP_MAX_SIZE_BODY) { // Finished
				crypto_secretstream_xchacha20poly1305_rekey(&ss_state);
				break;
			}

			if (lenEnc <= crypto_secretstream_xchacha20poly1305_ABYTES || lenEnc > AEM_SMTP_CHUNKSIZE + crypto_secretstream_xchacha20poly1305_ABYTES) {
				syslog(LOG_WARNING, "IntCom[SS] Invalid message length");
				break;
			}

			if (recv(sock, enc, lenEnc, MSG_WAITALL) != (ssize_t)lenEnc) {
				syslog(LOG_WARNING, "IntCom[SS] Failed receiving message");
				break;
			}

			if (crypto_secretstream_xchacha20poly1305_pull(&ss_state, dlv->src + dlv->lenSrc, NULL, &ss_tag, enc, lenEnc, NULL, 0) != 0 || (ss_tag != 0)) {
				syslog(LOG_WARNING, "IntCom[SS] Failed decrypting message (%zu bytes)", lenEnc);
				break;
			}

			dlv->lenSrc += lenEnc - crypto_secretstream_xchacha20poly1305_ABYTES;
		}

		if (dlv->lenSrc <= 1) {
			close(sock);
			continue;
		}

		const int32_t ret = deliverEmail(&dlv->meta, &dlv->info, dlv->src, dlv->lenSrc);
		sodium_memzero(dlv, sizeof(struct dlvEmail));
		send(sock, &ret, sizeof(int32_t), 0);

		close(sock);
	}

	free(dlv);
}
