#include <stdbool.h>
#include <syslog.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <sodium.h>

#include "../Global.h"

#define AEM_PEEROK_CLIENT
#include "peerok.h"

#include "Stream_Client.h"

static unsigned char intcom_key[crypto_secretbox_KEYBYTES];
static pid_t intcom_pid;

int ss_sock = -1;
crypto_secretstream_xchacha20poly1305_state ss_state;

void intcom_setKey_stream(const unsigned char newKey[crypto_secretstream_xchacha20poly1305_KEYBYTES]) {
	memcpy(intcom_key, newKey, crypto_secretbox_KEYBYTES);
}

void intcom_setPid_stream(const pid_t pid) {intcom_pid = pid;}

static int setSockOpts(void) {
	struct timeval tv;
	tv.tv_sec = 10;
	tv.tv_usec = 1;

	const int intTrue = 1;

	return (
	   setsockopt(ss_sock, SOL_SOCKET, SO_DONTROUTE, &intTrue, sizeof(int)) == 0
	&& setsockopt(ss_sock, SOL_SOCKET, SO_LOCK_FILTER, &intTrue, sizeof(int)) == 0
	&& setsockopt(ss_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(struct timeval)) == 0
	&& setsockopt(ss_sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(struct timeval)) == 0
	) ? 0 : -1;
}

static int intcom_socket(void) {
	struct sockaddr_un sa;
	sa.sun_family = AF_UNIX;

	memcpy(sa.sun_path, AEM_INTCOM_SOCKPATH_DELIVER, AEM_INTCOM_SOCKPATH_LEN);

	ss_sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (ss_sock < 0) {syslog(LOG_WARNING, "Failed creating IntCom Stream socket: %m"); return -1;}
	setSockOpts();

	if (connect(ss_sock, (struct sockaddr*)&sa, sizeof(sa.sun_family) + AEM_INTCOM_SOCKPATH_LEN) != 0) {
		syslog(LOG_WARNING, "Failed connecting to IntCom Stream socket: %m");
		close(ss_sock);
		ss_sock = -1;
		return -1;
	}

	if (!peerOk(ss_sock, intcom_pid)) {
		syslog(LOG_WARNING, "Invalid peer on IntCom Stream socket");
		close(ss_sock);
		ss_sock = -1;
		return -1;
	}

	return 0;
}

int intcom_stream_open(void) {
	if (intcom_socket() < 0) return -1;

	unsigned char ss_header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
	crypto_secretstream_xchacha20poly1305_init_push(&ss_state, ss_header, intcom_key);

	if (send(ss_sock, ss_header, crypto_secretstream_xchacha20poly1305_HEADERBYTES, 0) != crypto_secretstream_xchacha20poly1305_HEADERBYTES) {
		close(ss_sock);
		ss_sock = -1;
		syslog(LOG_ERR, "IntCom[SC]: Failed sending header: %m");
		return -1;
	}

	return 0;
}

int intcom_stream_send(const unsigned char * const src, const size_t lenSrc) {
	if (ss_sock < 0) return -1;

	const size_t lenEnc = lenSrc + crypto_secretstream_xchacha20poly1305_ABYTES;
	unsigned char enc[lenEnc];
	crypto_secretstream_xchacha20poly1305_push(&ss_state, enc, NULL, src, lenSrc, NULL, 0, 0);

	if (send(ss_sock, &lenEnc, sizeof(size_t), 0) != sizeof(size_t) || send(ss_sock, enc, lenEnc, 0) != (ssize_t)lenEnc) {
		close(ss_sock);
		ss_sock = -1;
		syslog(LOG_ERR, "IntCom[SC]: Failed sending message: %m");
		return -1;
	}

	return 0;
}

int32_t intcom_stream_end(void) {
	if (ss_sock < 0) return -1;

	crypto_secretstream_xchacha20poly1305_rekey(&ss_state);

	const size_t smax = SIZE_MAX;
	if (send(ss_sock, &smax, sizeof(size_t), 0) != sizeof(size_t)) {close(ss_sock); ss_sock = -1; syslog(LOG_ERR, "IntCom[SC]: Failed sending end-message: %m"); return AEM_INTCOM_RESPONSE_ERR;}

	int32_t res;
	if (recv(ss_sock, &res, sizeof(int32_t), MSG_WAITALL) != sizeof(int32_t)) {close(ss_sock); ss_sock = -1; syslog(LOG_ERR, "IntCom[SC]: Failed receiving result: %m"); return AEM_INTCOM_RESPONSE_ERR;}

	close(ss_sock);
	ss_sock = -1;
	return res;
}
