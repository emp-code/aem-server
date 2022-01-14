#include <stdbool.h>
#include <syslog.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <sodium.h>

#include "../Global.h"
#include "../Data/internal.h"

#include "IntCom_Client.h"

static const unsigned char *intcom_keys[] = {
#ifdef AEM_ACCOUNT
	AEM_KEY_INTCOM_STORAGE_ACC
#elif defined(AEM_API)
	AEM_KEY_INTCOM_ACCOUNT_API,
	AEM_KEY_INTCOM_ENQUIRY_API,
	AEM_KEY_INTCOM_STORAGE_API
#elif defined(AEM_MTA)
	AEM_KEY_INTCOM_ACCOUNT_MTA,
	AEM_KEY_INTCOM_ENQUIRY_MTA,
	AEM_KEY_INTCOM_STORAGE_MTA
#endif
};

static pid_t intcom_pids[4] = {0, 0, 0, 0};

#if defined(AEM_API) || defined(AEM_MTA)
void setAccountPid(const pid_t pid) {intcom_pids[AEM_INTCOM_TYPE_ACCOUNT] = pid;}
void setEnquiryPid(const pid_t pid) {intcom_pids[AEM_INTCOM_TYPE_ENQUIRY] = pid;}
#endif
void setStoragePid(const pid_t pid) {intcom_pids[AEM_INTCOM_TYPE_STORAGE] = pid;}

static int setSockOpts(const int sock) {
	struct timeval tv;
	tv.tv_sec = 10;
	tv.tv_usec = 1;

	const int intTrue = 1;

	return (
	   setsockopt(sock, SOL_SOCKET, SO_DONTROUTE, &intTrue, sizeof(int)) == 0
	&& setsockopt(sock, SOL_SOCKET, SO_LOCK_FILTER, &intTrue, sizeof(int)) == 0
	&& setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(struct timeval)) == 0
	&& setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(struct timeval)) == 0
	) ? 0 : -1;
}

static bool peerOk(const int sock, const aem_intcom_type_t intcom_type) {
	struct ucred peer;
	socklen_t lenUc = sizeof(struct ucred);
	if (getsockopt(sock, SOL_SOCKET, SO_PEERCRED, &peer, &lenUc) == -1) return false;
	return (peer.pid == intcom_pids[intcom_type] && peer.gid == getgid() && peer.uid == getuid());
}

static int intcom_socket(const aem_intcom_type_t intcom_type) {
	struct sockaddr_un sa;
	sa.sun_family = AF_UNIX;

	switch (intcom_type) {
		case AEM_INTCOM_TYPE_ACCOUNT: memcpy(sa.sun_path, AEM_SOCKPATH_ACCOUNT, AEM_SOCKPATH_LEN); break;
		case AEM_INTCOM_TYPE_ENQUIRY: memcpy(sa.sun_path, AEM_SOCKPATH_ENQUIRY, AEM_SOCKPATH_LEN); break;
		case AEM_INTCOM_TYPE_STORAGE: memcpy(sa.sun_path, AEM_SOCKPATH_STORAGE, AEM_SOCKPATH_LEN); break;
		default: return -1;
	}

	const int sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (sock < 0) {syslog(LOG_WARNING, "Failed creating IntCom socket: %m"); return -1;}
	setSockOpts(sock);

	if (connect(sock, (struct sockaddr*)&sa, sizeof(sa.sun_family) + 4) != 0) {
		syslog(LOG_WARNING, "Failed connecting to IntCom socket: %m");
		close(sock);
		return -1;
	}

	if (!peerOk(sock, intcom_type)) {
		syslog(LOG_WARNING, "Invalid peer on IntCom socket");
		close(sock);
		return -1;
	}

	return sock;
}

int32_t intcom(const aem_intcom_type_t intcom_type, const int operation, const unsigned char * const msg, const size_t lenMsg, unsigned char ** const out, const int32_t expectedLenOut) {
	if (intcom_type >= AEM_INTCOM_TYPE_NULL) return AEM_INTCOM_RESPONSE_ERR;
	const int sock = intcom_socket(intcom_type);
	if (sock < 0) return AEM_INTCOM_RESPONSE_ERR;

	// Create and send header
	const size_t lenEncHdr = 1 + sizeof(uint32_t) + crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES;
	unsigned char encHdr[lenEncHdr];
#ifdef AEM_ACCOUNT
	encHdr[0] = AEM_IDENTIFIER_ACC;
#elif defined(AEM_API)
	encHdr[0] = AEM_IDENTIFIER_API;
#elif defined(AEM_MTA)
	encHdr[0] = AEM_IDENTIFIER_MTA;
#else
	encHdr[0] = AEM_IDENTIFIER_INV;
#endif
	randombytes_buf(encHdr + 1, crypto_secretbox_NONCEBYTES);
	const uint32_t hdr = (operation << 24) | (lenMsg & UINT24_MAX); // 8 highest bits = operation, 24 lowest bits = size
	crypto_secretbox_easy(encHdr + 1 + crypto_secretbox_NONCEBYTES, (unsigned char*)&hdr, sizeof(uint32_t), encHdr + 1, intcom_keys[intcom_type]);
	if (send(sock, encHdr, lenEncHdr, 0) != lenEncHdr) {close(sock); syslog(LOG_ERR, "IntCom[C]: Failed sending header: %m"); return AEM_INTCOM_RESPONSE_ERR;}

	// Create and send message
	if (lenMsg > 0) {
		const size_t lenEncMsg = lenMsg + crypto_secretbox_MACBYTES;
		unsigned char * const encMsg = malloc(lenEncMsg);
		if (encMsg == NULL) {close(sock); syslog(LOG_ERR, "Failed allocation"); return AEM_INTCOM_RESPONSE_ERR;}
		sodium_increment(encHdr + 1, crypto_secretbox_NONCEBYTES);
		crypto_secretbox_easy(encMsg, msg, lenMsg, encHdr + 1, intcom_keys[intcom_type]);
		if (send(sock, encMsg, lenEncMsg, 0) != (ssize_t)lenEncMsg) {close(sock); syslog(LOG_ERR, "IntCom[C]: Failed sending message: %m"); return AEM_INTCOM_RESPONSE_ERR;}
	}

	// Receive response header
	const size_t lenRcvEnc = sizeof(int32_t) + crypto_secretbox_MACBYTES;
	unsigned char rcv_enc[lenRcvEnc];
	if (recv(sock, rcv_enc, lenRcvEnc, MSG_WAITALL) != lenRcvEnc) {close(sock); syslog(LOG_ERR, "IntCom[C]: Failed receiving header: %m"); return AEM_INTCOM_RESPONSE_ERR;}

	sodium_increment(encHdr + 1, crypto_secretbox_NONCEBYTES);
	int32_t lenOut = AEM_INTCOM_RESPONSE_ERR;
	if (crypto_secretbox_open_easy((unsigned char*)&lenOut, rcv_enc, lenRcvEnc, encHdr + 1, intcom_keys[intcom_type]) != 0) {close(sock); syslog(LOG_ERR, "IntCom[C]: Failed decrypting header"); return AEM_INTCOM_RESPONSE_ERR;}

	if (out == NULL || lenOut < 1) {
		close(sock);
		return lenOut;
	}

	if (expectedLenOut != 0 && lenOut != expectedLenOut) {close(sock); syslog(LOG_WARNING, "IntCom[C]: Response does not match expected length"); return AEM_INTCOM_RESPONSE_ERR;}

	// Receive response message
	*out = sodium_malloc(lenOut);
	if (*out == NULL) {close(sock); syslog(LOG_ERR, "Failed allocation"); return AEM_INTCOM_RESPONSE_ERR;}
	unsigned char mac[crypto_secretbox_MACBYTES];

	if (recv(sock, mac, crypto_secretbox_MACBYTES, MSG_WAITALL) != crypto_secretbox_MACBYTES || recv(sock, *out, lenOut, MSG_WAITALL) != (ssize_t)lenOut) {
		close(sock);
		sodium_free(*out);
		*out = NULL;
		syslog(LOG_ERR, "IntCom[C]: Failed receiving message: %m");
		return AEM_INTCOM_RESPONSE_ERR;
	}
	close(sock);

	sodium_increment(encHdr + 1, crypto_secretbox_NONCEBYTES);
	if (crypto_secretbox_open_detached(*out, *out, mac, lenOut, encHdr + 1, intcom_keys[intcom_type]) != 0) {sodium_free(*out); *out = NULL; return AEM_INTCOM_RESPONSE_ERR;}

	return lenOut;
}
